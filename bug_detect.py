import logging

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# logging.basicConfig(filename="newfile.log",
#                     format='%(asctime)s %(message)s',
#                     filemode='w')
def use_of_tx_origin(file_name):
    try:
        with open(file_name) as f:
            for s in f:
                if "tx.origin" in s:
                    logger.warning("USE OF tx.origin , POSSIBLE VULNERABILITY")
    except:
        pass
def use_of_timestamp(file_name):
    with open(file_name) as f:
        for s in f:
            if "block.timestamp" in s:
                logger.warning("USE OF block.timestamp , POSSIBLE VULNERABILITY")
def gasless_send(file_name):
    try:
        with open(file_name) as f:
            for s in f:
                if ".send(" in s:
                        logger.error("USE OF send , POSSIBLE VULNERABILITY")
    except:
        pass

def 

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
    use_of_tx_origin(file_name)
    use_of_timestamp(file_name)
    gasless_send(file_name)
    reentrancy(file_name)