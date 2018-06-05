# Script to create new lint from template

if [ $# -eq 0 ]; then
    echo "No arguments provided..."
    echo "ARG1: File_name/TestName"
    echo "ARG2: Struct_name"
    exit 1
fi

if [ $# -eq 1 ]; then
    echo "Not enough arguments provided..."
    echo "ARG1: File_name/TestName"
    echo "ARG2: Struct_name"
    exit 1
fi

if [ -e lint_$1.go ]
then
   echo "File already exists. Can't make new file."
   exit 1
fi

FILENAME=$1
TESTNAME=$2

cp template lints/lint_$FILENAME.go

cat "lints/lint_$FILENAME.go" | sed "s/SUBST/$2/g" | sed "s/SUBTEST/$1/g" > temp.go
mv -f temp.go "lints/lint_$FILENAME.go"

echo "Created file lint_$FILENAME.go with test name $TESTNAME"
