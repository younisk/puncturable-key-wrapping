project(tests)

# For google tests
include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
# adding the Google_Tests_run target
add_executable(Google_Tests_run NaivePKWTest.cpp GGM_PPRFTest.cpp PPRF_AEAD_PKWTest.cpp)

include(GoogleTest)
gtest_discover_tests(Google_Tests_run)
# linking Google_Tests_run with puncturable-key-wrapping-cpp_lib which will be tested
target_link_libraries(Google_Tests_run PKWLib GTest::gtest_main GTest::gmock_main)
add_test(Google_Tests_run NaivePKWTest.cpp)
add_test(Google_Tests_run GGM_PPRFTest.cpp)
add_test(Google_Tests_run PPRF_AEAD_PKWTest.cpp)

#include(GoogleTest)

add_executable(Benchmarks SerializationSizeBenchmarksPPRF.cpp)
target_link_libraries(Benchmarks PKWLib)

add_custom_command(TARGET Benchmarks POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/puncturable-key-wrapping-cpp_tests/resources/ $<TARGET_FILE_DIR:Benchmarks>)