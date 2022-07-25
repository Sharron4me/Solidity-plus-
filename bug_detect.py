import logging
from csv import DictWriter
import os
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# logging.basicConfig(filename="newfile.log",
#                     format='%(asctime)s %(message)s',
#                     filemode='w')
def use_of_tx_origin(file_name):
    try:
        flag=0
        with open(file_name) as f:
            line = 0
            for s in f:
                line+=1
                if "tx.origin" in s:
                    logger.warning("USE OF tx.origin , POSSIBLE VULNERABILITY")
                    with open('report.csv', 'a') as f_object:
                        # Pass the file object and a list
                        # of column names to DictWriter()
                        # You will get a object of DictWriter
                        dictwriter_object = DictWriter(f_object, fieldnames=['filename', 'Bug comment'])

                        # Pass the dictionary as an argument to the Writerow()
                        dictwriter_object.writerow(
                            {'filename': file_name, 'Bug comment': 'Use Of Tx.origin Bug in line : ' + str(line)})

                        # Close the file object
                        f_object.close()
                        flag = 1
        if flag:
            return False
    except:
        pass
    return True
def use_of_timestamp(file_name):
    flag=0
    with open(file_name) as f:
        line=0
        for s in f:
            line+=1
            if "block.timestamp" in s:
                logger.warning("USE OF block.timestamp , POSSIBLE VULNERABILITY")
                with open('report.csv', 'a') as f_object:
                    # Pass the file object and a list
                    # of column names to DictWriter()
                    # You will get a object of DictWriter
                    dictwriter_object = DictWriter(f_object, fieldnames=['filename', 'Bug comment'])

                    # Pass the dictionary as an argument to the Writerow()
                    dictwriter_object.writerow(
                        {'filename': file_name, 'Bug comment': 'block.timestamp Bug in line : ' + str(line)})

                    # Close the file object
                    f_object.close()
                flag=1
    if flag:
        return False
    return True
def gasless_send(file_name):
    try:
        flag=0
        with open(file_name) as f:
            line=0
            for s in f:
                line+=1
                if ".send(" in s or "msg.sender.transfer(" in s:
                    logger.error("Use Of send , POSSIBLE VULNERABILITY")
                    with open('report.csv', 'a') as f_object:
                        # Pass the file object and a list
                        # of column names to DictWriter()
                        # You will get a object of DictWriter
                        dictwriter_object = DictWriter(f_object, fieldnames=['filename','Bug comment'])

                        # Pass the dictionary as an argument to the Writerow()
                        dictwriter_object.writerow({'filename':file_name,'Bug comment':'Use Of send Bug in line : '+str(line)})

                        # Close the file object
                        f_object.close()
                    flag=1
        if flag:
           return False
    except:
        pass
    return True
def arithmetic_overflow(filename,path):

    pass


def reentrancy(file_name):
    try:
        isconstructor =True
        addFunction=True
        opencount=0
        output=[]
        with open(file_name) as f:
            for s in f:
                s=s.strip()
                t=list(s.split(" "))
                if(t[0]=="contract"):
                    addFunction=False
                    output.append("\n string[] callStack;\n uint flag;\n event checkMsg(string message);\n")
                    opencount+=1
                elif(t[0]=="function"):
                    if(" view " in s):
                        s.replace(" view "," ")
                    functionName = t[1].split("(")
                    output.append(s + '\n emit checkMsg(\"Checking Reentrancy\"); \n checkReentrancy(\"' + functionName[0] +'"\");\n callStack.push(\""'+ functionName[0] + '"\");\n')
                    opencount+=1
                elif (t[0]=="function()"):
                    output.append(s + '\n emit checkMsg(\"Checking Reentrancy\"); \n checkReentrancy(\"fallback\");\n callStack.push(\"fallback\");\n')
                    opencount+=1
                elif (t[0]=="return"):
                    output.append("\n delete callStack[callStack.length-1];\n callStack.length--;\n" + s)
                else:
                    if not addFunction and opencount==1:
                        output.append('function checkReentrancy(string memory functionName) public { \n if(callStack.length > 0){ \n for(uint i=callStack.length; i>0; i--) { \n if(keccak256(abi.encodePacked(callStack[i-1])) == keccak256(abi.encodePacked(functionName))) \n flag = 0; \n } \n } else \n flag = 1; \n\n require(flag==1, \"Possibility of reentrancy\"); \n} \n;')
                        addFunction=True
                    if s.startswith("constructor"):
                        output.append(s+"\n")
                        isconstructor=True
                        opencount+=1
                    elif "}" in s and opencount==2:
                        if "return" in s:
                            opencount-=1
                            output.append(s)
                        else:
                            if isconstructor:
                                output.append(s)
                                opencount-=1
                                isconstructor=False
                            else:
                                output.append("\n delete callStack[callStack.length-1];\n callStack.length--;\n" +s)
                                opencount-=1
                    if "{" in s:
                        opencount+=1
                    elif "}" in s:
                        opencount-=1
                    if "send(" in s:
                        output.append("require(" + s.split(";")[0] + ", \"Send Failed!!\"); \n")
                    else:
                        output.append(s)
        file1 = open("solidified_" + file_name[3:], 'w')
        file1.writelines(output)
        file1.close()
    except Exception as e:
        print(e)


def check_all(file_name):
    flag=0
    if(not use_of_tx_origin(file_name)):
        flag=1
        print("Bug 1 File Name:",file_name)
    if(not use_of_timestamp(file_name)):
        flag = 1
        print("Bug 2 File Name:", file_name)
    if(not gasless_send(file_name)):
        flag = 1
        print("Bug 3 File Name:",file_name)
    # if(not reentrancy(file_name)):
    #     flag = 1
    if(flag):
        return False
    return True