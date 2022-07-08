def remove_comment(file_name):
    comment_is_open = False
    output = []
    new_string = ""
    with open(file_name) as f:
        source = f.readlines()
        for s in source:
            if comment_is_open == False:
                new_string = ""
            i = 0
            while i < len(s):
                if (i != len(s) - 1 and s[i] + s[i+1] == "//" and comment_is_open == False):
                    break
                if i != len(s) - 1 and s[i] + s[i+1] == "/*" and comment_is_open == False:
                    comment_is_open = True
                    i += 2
                    continue
                if i != len(s) - 1 and s[i] + s[i+1] == "*/" and comment_is_open == True:
                    comment_is_open = False
                    i += 2
                    continue
                if comment_is_open == False:
                    new_string += s[i]
                i += 1
            if new_string != "" and comment_is_open == False:
                output.append(new_string)
        file1 = open("NC_"+file_name, 'w')
        file1.writelines(output)
        file1.close()
