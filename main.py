from preprocessor import *
from bug_detect import *
file_name=""
with open('configure.txt') as f:
    file_name= f.readlines()[0]
remove_comment(file_name)
check_all("NC_"+file_name)
input("Enter a key to exit\n")
print(file_name)

