from preprocessor import *
from bug_detect import *
file_names=""
result=0
with open('configure.txt') as f:
    file_names= f.readlines()
    os.chdir('Bug_database/Unchecked_Send')
    for file_name in file_names:
        remove_comment(file_name[:-1])
        print(file_name)
        if(not check_all("NC_"+file_name[:-1],)):
            print('Problem')
            result+=1
print(result)

