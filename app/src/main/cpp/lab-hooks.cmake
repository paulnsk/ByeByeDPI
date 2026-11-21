# The pinned submodule stays intact. Instrument generated copies of two files.
function(lab_replace input marker hook)
    string(FIND "${${input}}" "${marker}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "ByeDPI observation anchor missing")
    endif()
    string(REPLACE "${marker}" "${hook}" content "${${input}}")
    set("${input}" "${content}" PARENT_SCOPE)
endfunction()

function(lab_hook unit)
    set(source "${CMAKE_CURRENT_SOURCE_DIR}/byedpi/${unit}.c")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    file(READ "${source}" content)
    if(unit STREQUAL "extend")
        lab_replace(content "    save_hostname(client, buffer, n);"
            "    save_hostname(client, buffer, n);\n    lab_client_hello(client->pair->fd, buffer, n);")
        set(marker "    remote->pair->round_sent += sn;")
        lab_replace(content "${marker}"
            "    if (remote->flag == FLAG_CONN && sn > 0 && *n >= (ssize_t)off\n        && sn >= *n - (ssize_t)off) {\n        int ms = lab_arm_hello_wait(remote->fd);\n        if (ms > 0) set_timer(pool, remote, ms);\n    }\n${marker}")
        set(marker "    val->recv_count += n;")
        lab_replace(content "${marker}"
            "    if (val->flag == FLAG_CONN && lab_finish_hello_wait(val->fd, 0))\n        remove_timer(pool, val);\n${marker}")
        set(marker "int on_timeout(struct poolhd *pool, struct eval *val) {")
        lab_replace(content "${marker}"
            "${marker}\n    if (lab_finish_hello_wait(val->fd, 1)) return on_torst(pool, val);")
    else()
        lab_replace(content "        if (!error) error = ECONNREFUSED;"
            "        if (!error) error = ECONNREFUSED;\n        lab_tcp_status(val->fd, error);")
        set(marker "        val->cb = &on_tunnel;\n        val->pair->cb = &on_tunnel;")
        lab_replace(content "${marker}" "        lab_tcp_status(val->fd, 0);\n${marker}")
    endif()
    set(output "${CMAKE_CURRENT_BINARY_DIR}/lab-${unit}.c")
    file(GENERATE OUTPUT "${output}" CONTENT "#include \"lab-traffic.h\"\n${content}")
    set(sources ${BYE_DPI_SRC})
    list(REMOVE_ITEM sources "${source}")
    list(APPEND sources "${output}")
    set(BYE_DPI_SRC "${sources}" PARENT_SCOPE)
endfunction()

lab_hook(extend)
lab_hook(proxy)
