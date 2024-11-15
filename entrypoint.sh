#!/bin/sh
sysctl kernel.randomize_va_space=0

./syso ./main hello world
