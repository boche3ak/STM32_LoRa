execute_process(
    COMMAND ${OBJDUMP} -h ${ELF_FILE}
    OUTPUT_VARIABLE sections
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Helper: pad string to fixed width with trailing spaces
macro(pad_string result str width)
    string(LENGTH "${str}" _len)
    math(EXPR _pad "${width} - ${_len}")
    if(_pad GREATER 0)
        string(REPEAT " " ${_pad} _spaces)
        set(${result} "${str}${_spaces}")
    else()
        set(${result} "${str}")
    endif()
endmacro()

message(STATUS "FoF NVRAM section layout:")
message(STATUS "  +--------------------------+------------+--------+")
message(STATUS "  | Section                  | Address    | Size   |")
message(STATUS "  +--------------------------+------------+--------+")

string(REPLACE "\n" ";" lines "${sections}")
foreach(line IN LISTS lines)
    if(line MATCHES "^[ ]+[0-9]+ (\\.fof_[^ ]+)[ ]+([0-9a-fA-F]+)[ ]+([0-9a-fA-F]+)")
        set(sec_name "${CMAKE_MATCH_1}")
        set(sec_size "${CMAKE_MATCH_2}")
        set(sec_vma  "${CMAKE_MATCH_3}")
        math(EXPR size_dec "0x${sec_size}")
        pad_string(name_col "${sec_name}"       24)
        pad_string(size_col "${size_dec} B"      6)
        message(STATUS "  | ${name_col} | 0x${sec_vma} | ${size_col} |")
    endif()
endforeach()

message(STATUS "  +--------------------------+------------+--------+")
