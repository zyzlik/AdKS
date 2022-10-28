#!/bin/bash

files=( $(git diff origin/master --diff-filter=d --name-only "*.yaml" :^.github) )
input=""
base=""
declare -p files
if [[ ${files[@]} -eq 0 ]]; then
    echo "no secret file changes detected"
    echo "should_update=false" >> $GITHUB_ENV
else
    echo "secret file changes detected"
    echo "should_update=true" >> $GITHUB_ENV
fi
for i in ${files[@]} ; do
    if [ -z "$input" ]
    then
        input=$i
    else
        input+=",$i"
    fi

    if ! git show origin/master:$i > base-$i
    #git show origin/master:$i > temp-$i

    then
        echo "file $i not found on master it must be new"
        #net new secrets file, we don't need a base copy
        rm "base-$i"
        continue
    else
        if [ -z "$base" ]
        then
            base=base-$i
        else
            base+=",base-$i"
        fi
    fi
done
echo "input string is $input"
echo "base string is $base"
echo "base-secrets=$base" >> $GITHUB_ENV
echo "input-secrets=$input" >> $GITHUB_ENV