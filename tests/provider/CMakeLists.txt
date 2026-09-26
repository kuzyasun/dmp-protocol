# Private P01 experiment seam. No provider is selected or downloaded by P00.
function(dmp_add_provider_experiment name)
    add_executable(${name} ${ARGN})
    set_target_properties(${name} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /WX)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 30 LABELS "provider-experiment")
endfunction()

dmp_add_provider_experiment(dmp_host_environment host_environment.c)
set_tests_properties(dmp_host_environment PROPERTIES LABELS "scaffold-only")

if(DMP_NOISE_EXPERIMENTS)
    include(noise_experiment.cmake)
endif()
