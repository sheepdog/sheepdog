cmake_minimum_required(VERSION 2.8)

SET(DynamoRIO_DIR "~/dynamorio/exports/cmake")
find_package(DynamoRIO)

add_library(journaling SHARED journaling.c ../common.c)
configure_DynamoRIO_client(journaling)

use_DynamoRIO_extension(journaling drwrap)
use_DynamoRIO_extension(journaling drcontainers)
