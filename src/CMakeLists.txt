include_directories(.)

add_executable(
  main

  main.cpp
)



target_link_libraries(
  main

  snark
)

target_include_directories(
  main

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

add_library(
    mainlib
    SHARED
    
    main.cpp
)


target_link_libraries(
  mainlib
 "-Wl,--whole-archive"
  snark
  "-Wl,--no-whole-archive"
)

target_include_directories(
  mainlib

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
