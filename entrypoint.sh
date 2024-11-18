#!/bin/sh
sysctl kernel.randomize_va_space=0

./bin/syso ./main hello world
