# Column widths
set(COL_NAME  32)
set(COL_ADDR  12)
set(COL_SIZE   6)

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

# Build separator line from column widths
macro(make_separator result)
    string(REPEAT "-" ${COL_NAME}  _n)
    string(REPEAT "-" ${COL_ADDR}  _a)
    string(REPEAT "-" ${COL_SIZE}  _s)
    set(${result} "  +-${_n}-+-${_a}-+-${_s}-+")
endmacro()

# Collect fof_ sections from objdump -h
execute_process(
    COMMAND ${OBJDUMP} -h ${ELF_FILE}
    OUTPUT_VARIABLE objdump_out
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Collect Cfg_ symbols: store as "addr|size|name" (| avoids CMake list separator issues)
execute_process(
    COMMAND ${NM} --print-size --defined-only ${ELF_FILE}
    OUTPUT_VARIABLE nm_out
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(cfg_symbols "")
string(REPLACE "\n" ";" nm_lines "${nm_out}")
foreach(line IN LISTS nm_lines)
    if(line MATCHES "^([0-9a-fA-F]+) ([0-9a-fA-F]+) [A-Za-z] (Cfg_[^ ]+)")
        list(APPEND cfg_symbols "${CMAKE_MATCH_1}|${CMAKE_MATCH_2}|${CMAKE_MATCH_3}")
    endif()
endforeach()

make_separator(SEP)
pad_string(hdr_name "Section / Symbol" ${COL_NAME})
pad_string(hdr_addr "Address"          ${COL_ADDR})
pad_string(hdr_size "Size"             ${COL_SIZE})

message(STATUS "FoF NVRAM section layout:")
message(STATUS "${SEP}")
message(STATUS "  | ${hdr_name} | ${hdr_addr} | ${hdr_size} |")
message(STATUS "${SEP}")

string(REPLACE "\n" ";" objdump_lines "${objdump_out}")
foreach(line IN LISTS objdump_lines)
    if(line MATCHES "^[ ]+[0-9]+ (\\.fof_[^ ]+)[ ]+([0-9a-fA-F]+)[ ]+([0-9a-fA-F]+)")
        set(sec_name "${CMAKE_MATCH_1}")
        set(sec_size "${CMAKE_MATCH_2}")
        set(sec_vma  "${CMAKE_MATCH_3}")
        math(EXPR size_dec "0x${sec_size}")
        pad_string(name_col "${sec_name}"    ${COL_NAME})
        pad_string(addr_col "0x${sec_vma}"  ${COL_ADDR})
        pad_string(size_col "${size_dec} B" ${COL_SIZE})
        message(STATUS "  | ${name_col} | ${addr_col} | ${size_col} |")

        # For .fof_config expand each Cfg_ symbol as a sub-row
        if(sec_name STREQUAL ".fof_config")
            foreach(sym IN LISTS cfg_symbols)
                string(REPLACE "|" ";" parts "${sym}")
                list(GET parts 0 sym_addr)
                list(GET parts 1 sym_size)
                list(GET parts 2 sym_name)
                math(EXPR sym_size_dec "0x${sym_size}")
                pad_string(sym_name_col "  ${sym_name}" ${COL_NAME})
                pad_string(sym_addr_col "0x${sym_addr}" ${COL_ADDR})
                pad_string(sym_size_col "${sym_size_dec} B" ${COL_SIZE})
                message(STATUS "  | ${sym_name_col} | ${sym_addr_col} | ${sym_size_col} |")
            endforeach()
            message(STATUS "${SEP}")
        endif()
    endif()
endforeach()

message(STATUS "${SEP}")
