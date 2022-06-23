cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(zeek-client)

set(ZEEK_BIN_DIR ${CMAKE_INSTALL_PREFIX}/bin)

# Define the default config file location.
set(ZEEK_CLIENT_CONFIG_FILE "${ZEEK_ETC_INSTALL_DIR}/zeek-client.cfg")

if ( NOT PY_MOD_INSTALL_DIR )
    # This is not a Zeek-bundled install. Default to "home"-style install.
    set(PY_MOD_INSTALL_DIR lib/python)
endif ()

# Install zeek-client with updated content:
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/zeek-client
    ${CMAKE_CURRENT_BINARY_DIR}/zeek-client @ONLY)
install(DIRECTORY DESTINATION bin)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/zeek-client DESTINATION bin)

# Install the Python module tree. Use a pattern match to avoid installing any
# .pyc or __pycache__ files that might reside in the directory due to local
# unit-testing.
install(DIRECTORY DESTINATION ${PY_MOD_INSTALL_DIR})
install(DIRECTORY zeekclient DESTINATION ${PY_MOD_INSTALL_DIR}
    FILES_MATCHING PATTERN "zeekclient/*.py"
    PATTERN "__pycache__" EXCLUDE)

# Install the constants file with updated content:
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/zeekclient/consts.py
    ${CMAKE_CURRENT_BINARY_DIR}/zeekclient/consts.py @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zeekclient/consts.py
    DESTINATION ${PY_MOD_INSTALL_DIR}/zeekclient)

message(
    "\n==================|  zeek-client Build Summary  |==============="
    "\n"
    "\nInstall prefix:      ${CMAKE_INSTALL_PREFIX}"
    "\nPython module path:  ${PY_MOD_INSTALL_DIR}"
    "\n"
    "\n================================================================\n"
)
