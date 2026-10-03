#include "manifest.h"
#include "scenario.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#ifndef _WIN32
#include <signal.h>
#endif

#define STDERR_MAX 4096U

static size_t stderr_used;

static void note(const char *text)
{
    size_t n = strlen(text);
    if (stderr_used >= STDERR_MAX) {
        return;
    }
    if (n > STDERR_MAX - stderr_used) {
        n = STDERR_MAX - stderr_used;
    }
    fwrite(text, 1, n, stderr);
    stderr_used += n;
}

static int emit_closed(const char *outcome, int exit_code)
{
    char line[320];
    int wrote = snprintf(line, sizeof line,
                         "{\"seq\":0,\"time_ms\":0,\"event\":\"run_end\",\"outcome\":\"%s\","
                         "\"exit_code\":%d,\"stress\":false,\"accepted\":0,\"rejected\":0,"
                         "\"delivered\":0,\"terminal\":0,\"pending_local_at_horizon\":0,"
                         "\"pending_delivery_at_horizon\":0,\"events\":0}\n",
                         outcome, exit_code);
    if (wrote < 0 || (size_t)wrote >= sizeof line) {
        return 0;
    }
    if (fwrite(line, 1, (size_t)wrote, stdout) != (size_t)wrote || fflush(stdout) != 0) {
        return 0;
    }
    return 1;
}

static int exit_after_closed(const char *outcome, int exit_code)
{
    if (!emit_closed(outcome, exit_code)) {
        return 4;
    }
    return exit_code;
}

static int read_all(FILE *file, size_t limit, uint8_t **out, size_t *length)
{
    size_t cap = limit + 1U;
    size_t used = 0;
    uint8_t *buf = malloc(cap);
    if (buf == NULL) {
        return -1;
    }
    while (used < cap) {
        size_t got = fread(buf + used, 1, cap - used, file);
        if (got == 0U) {
            if (ferror(file)) {
                free(buf);
                return -1;
            }
            break;
        }
        used += got;
    }
    if (used > limit) {
        free(buf);
        return 1;
    }
    *out = buf;
    *length = used;
    return 0;
}

static int option_is(const char *arg, const char *name)
{
    return strcmp(arg, name) == 0;
}

int main(int argc, char **argv)
{
    const char *manifest_path = NULL;
    int version = 0;
    int i;
    uint8_t *scenario_bytes = NULL;
    uint8_t *manifest_bytes = NULL;
    size_t scenario_len = 0;
    size_t manifest_len = 0;
    harness_plan plan;
    manifest_view view;
    manifest_failure failure;
    harness_binding binding;
    char *trace;
    harness_result result;
    int parsed;
    int validated;
    size_t action;

#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    memset(&plan, 0, sizeof plan);
    memset(&view, 0, sizeof view);
    memset(&failure, 0, sizeof failure);
    memset(&binding, 0, sizeof binding);
    memset(&result, 0, sizeof result);

    for (i = 1; i < argc; i++) {
        if (option_is(argv[i], "--interface-version")) {
            if (version || manifest_path != NULL) {
                note("E_CLI\n");
                return 2;
            }
            version = 1;
        } else if (option_is(argv[i], "--manifest")) {
            if (version || manifest_path != NULL || i + 1 >= argc) {
                note("E_CLI\n");
                return 2;
            }
            manifest_path = argv[++i];
        } else {
            note("E_CLI\n");
            return 2;
        }
    }
    if (version) {
        if (fwrite("1\n", 1, 2, stdout) != 2U || fflush(stdout) != 0) {
            return 4;
        }
        return 0;
    }
    if (manifest_path == NULL) {
        note("E_CLI\n");
        return 2;
    }
    {
        int read_status = read_all(stdin, HARNESS_SCENARIO_MAX_BYTES, &scenario_bytes, &scenario_len);
        FILE *manifest;
        if (read_status != 0) {
            note(read_status < 0 ? "E_IO\n" : "E_SCENARIO\n");
            return exit_after_closed(read_status < 0 ? "internal_error" : "invalid_input",
                                     read_status < 0 ? 4 : 2);
        }
        manifest = fopen(manifest_path, "rb");
        if (manifest == NULL) {
            note("E_IO\n");
            free(scenario_bytes);
            return exit_after_closed("internal_error", 4);
        }
        read_status = read_all(manifest, MANIFEST_MAX_BYTES, &manifest_bytes, &manifest_len);
        fclose(manifest);
        if (read_status != 0) {
            int status;
            note(read_status < 0 ? "E_IO\n" : "E_MANIFEST code=encoding path=$\n");
            status = exit_after_closed(read_status < 0 ? "internal_error" : "invalid_input",
                                       read_status < 0 ? 4 : 2);
            free(scenario_bytes);
            free(manifest_bytes);
            return status;
        }
    }
    parsed = scenario_parse(scenario_bytes, scenario_len, &plan);
    if (parsed != 0) {
        int status;
        note(parsed == 3 ? "E_BUDGET\n" : parsed == 4 ? "E_IO\n" : "E_SCENARIO\n");
        status = exit_after_closed(parsed == 3 ? "budget_exhausted" : parsed == 4 ? "internal_error" : "invalid_input",
                                   parsed == 3 ? 3 : parsed == 4 ? 4 : 2);
        free(scenario_bytes);
        free(manifest_bytes);
        return status;
    }
    validated = manifest_validate(manifest_bytes, manifest_len, plan.sha256,
                                  DMP_MANIFEST_SCHEMA_PATH, &view, &failure);
    if (validated != 0) {
        char line[256];
        if (validated < 0) {
            note("E_IO\n");
            scenario_plan_free(&plan);
            free(scenario_bytes);
            free(manifest_bytes);
            return exit_after_closed("internal_error", 4);
        }
        snprintf(line, sizeof line, "E_MANIFEST code=%s path=%s\n", failure.code, failure.path);
        note(line);
        scenario_plan_free(&plan);
        free(scenario_bytes);
        free(manifest_bytes);
        return exit_after_closed("invalid_input", 2);
    }
    for (action = 0; action < plan.nactions; action++) {
        if (!plan.actions[action].cancel && plan.actions[action].data_len > view.encoded_mtu) {
            note("E_SCENARIO\n");
            scenario_plan_free(&plan);
            free(scenario_bytes);
            free(manifest_bytes);
            return exit_after_closed("invalid_input", 2);
        }
    }
    binding.encoded_mtu = view.encoded_mtu;
    binding.frame_tx_ms = view.frame_tx_ms;
    binding.delay_ms[0] = view.forward_delay_ms;
    binding.delay_ms[1] = view.return_delay_ms;
    binding.period_ms = view.period_ms;
    binding.width_ms = view.width_ms;
    binding.queue_ms = view.queue_ms;
    binding.adapter_slots = view.adapter_slots;
    binding.borrow = view.borrow;
    binding.synchronous_completion = view.synchronous_completion;
    binding.until_ms = plan.until_ms;
    binding.seed = plan.seed;
    binding.loss_threshold = plan.loss_threshold;
    binding.stress = plan.stress;
    memcpy(binding.sha256, plan.sha256, sizeof binding.sha256);
    memcpy(binding.seed_text, plan.seed_text, sizeof binding.seed_text);
    trace = malloc(HARNESS_MAX_TRACE_BYTES);
    if (trace == NULL) {
        note("E_IO\n");
        scenario_plan_free(&plan);
        free(scenario_bytes);
        free(manifest_bytes);
        return exit_after_closed("internal_error", 4);
    }
    if (harness_execute(&binding, plan.actions, plan.nactions, plan.faults, plan.nfaults, trace,
                        HARNESS_MAX_TRACE_BYTES, &result) != 0) {
        note("E_IO\n");
        free(trace);
        scenario_plan_free(&plan);
        free(scenario_bytes);
        free(manifest_bytes);
        return exit_after_closed("internal_error", 4);
    }
    if (fwrite(trace, 1, result.trace_len, stdout) != result.trace_len || fflush(stdout) != 0) {
        note("E_IO\n");
        free(trace);
        scenario_plan_free(&plan);
        free(scenario_bytes);
        free(manifest_bytes);
        return 4;
    }
    free(trace);
    scenario_plan_free(&plan);
    free(scenario_bytes);
    free(manifest_bytes);
    return result.exit_code;
}
