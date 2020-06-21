#!/bin/bash

IFS=$'\n'  #to Loop by line

old_processes=$(ps -eo command)
#echo $old_processes
#echo "$old_processes"

while true;
do
    new_processes=$(ps -eo command);
    diff <(echo "$old_processes") <(echo "$new_processes");
    old_processes=$(echo "$new_processes");
    sleep 1;
done
