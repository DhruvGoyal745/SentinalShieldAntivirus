add_executable(sentinel_engine_daemon
    src/main.cpp
)

target_link_libraries(sentinel_engine_daemon PRIVATE sentinel_engine_core)
