add_subdirectory(crypto)
add_subdirectory(ipc)
add_subdirectory(mgmt)
add_subdirectory_ifdef(CONFIG_FNMATCH fnmatch)
