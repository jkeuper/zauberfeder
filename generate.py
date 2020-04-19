#!/usr/bin/env python

templatesPath = "./templates/"

import os
import re
import sys
import glob
import shutil
import subprocess
import HTMLParser

def getValue(line):
    index = line.index(":")
    return line[index+1:].strip(" '\"")

def readTemplate(name):
    curpath = os.path.dirname(os.path.abspath(__file__))
    templatefile = os.path.join(curpath, templatesPath, name + ".tex")
    with open(templatefile) as f:
        content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        content = [x.strip("\n") for x in content]
        return "\n".join(content)

class Settings:
    def __init__(self, textfile):
        self._exercisespath = None

        with open(textfile) as f:
            content = f.readlines()
            # remove whitespace characters like `\n` at the end of each line
            content = [x.strip("\n") for x in content]

            foundStart = False
            for line in content:
                if not foundStart and line.startswith("---"):
                    foundStart = True
                    continue
                if not foundStart:
                    continue
                if  line.startswith("---"):
                    break

                if line.lower().startswith("fullname:"):
                    self._fullname = getValue(line)
                elif line.lower().startswith("firstname:"):
                    self._firstname = getValue(line)
                elif line.lower().startswith("osid:"):
                    self._osid = getValue(line)
                elif line.lower().startswith("version:"):
                    self._version = getValue(line)
                elif line.lower().startswith("email:"):
                    self._email = getValue(line)
                elif line.lower().startswith("hosts:"):
                    self._hosts = [x.strip() for x in getValue(line).split(",")]
                elif line.lower().startswith("hostspath:"):
                    self._hostspath = os.path.expanduser(getValue(line))
                elif line.lower().startswith("exercisespath:"):
                    self._exercisespath = os.path.expanduser(getValue(line))
                elif line.lower().startswith("outputfile:"):
                    self._outputfile = os.path.expanduser(getValue(line))

def parseHightlights(line):
    res = []
    try:
        line = line.strip('` ')
        if "{" in line and "}" in line:
            ranges = line[line.index('{')+1:line.index('}')]
            ranges = ranges.replace(" ", "")
            for range in ranges.split(","):
                if "-" in range:
                    parts = range.split("-")
                    res.append((int(parts[0]), int(parts[1])))
                else:
                    res.append((int(range),))
    except:
        print "WARNING: parsing code highlighting failed!"
        print line
    
    return res

def escapeAndSimpleFormat(line):
    html = HTMLParser.HTMLParser()
    line = html.unescape(line)
    # \& \% \$ \# \_ \{ \}

    #line = line.replace("\\", "\\textbackslash")
    #line = line.replace("~", "\\textasciitilde")

    line = line.replace("\\", "\\char`\\\\")

    line = line.replace("&", "\\&")
    line = line.replace("%", "\\%")
    line = line.replace("$", "\\$")
    line = line.replace("#", "\\#")
    line = line.replace("{", "\\{")
    line = line.replace("}", "\\}")

    #line = line.replace("\\textbackslash", "\\{textbackslash}")
    #line = line.replace("\\extasciitilde", "\\{textasciitilde}")

    if "<" in line:
        for word in line.split(" "):
            if word.startswith("<") and word.endswith(">"):
                url = readTemplate("urlplain")
                url = url.replace("<CONTENT>", word.strip("<>"))
                line = line.replace(word, url) 

    if "[" in line:
        index = line.index("[")
        indexEnd = line.index("]", index)
        if line[indexEnd+1] == "(":
            otherEnd = line.index(")", indexEnd)
            if indexEnd > 0 and otherEnd > 0:
                caption = line[index+1: indexEnd]
                content = line[indexEnd+2: otherEnd]
                template = readTemplate("url")
                template = template.replace("<CAPTION>", caption)
                template = template.replace("<CONTENT>", content)
                line = line.replace(line[index: otherEnd+1], template)
 
    if re.search(" [*_]+[A-Z-a-z0-9]", line):
        splitted = re.split("\.| ", line)
        for word in splitted:
            prefix = word[0:len(word)-len(word.lstrip("*_"))]
            if prefix == "":
                continue
            if word.endswith(prefix):
                if len(prefix) == 1:
                    line = line.replace(word, "\\textit{"+word[1:-1]+"}")
                elif len(prefix) == 2:
                    line = line.replace(word, "\\textbf{"+word[2:-2]+"}")
            else:
                if len(prefix) == 1:
                    line = line.replace(word, "\\textit{"+word[1:]+"}")
                elif len(prefix) == 2:
                    line = line.replace(word, "\\textbf{"+word[2:]+"}")

                for subword in splitted:
                    if subword.endswith(prefix):
                        line = line.replace(subword, subword[0:-1*len(prefix)]+"}")

    line = line.replace("_", "\\_")

    return line

def needsHighlight(codeLine, highlights):
    for highlight in highlights:
        if len(highlight) == 1:
            if codeLine == highlight[0]:
                return True
        else:
            if highlight[0] <= codeLine and codeLine <= highlight[1]:
                return True

    return False

def parseLists(content):
    firstItem = content[0]
    prefix = firstItem[0:len(firstItem) - len(firstItem.lstrip())]
    isOrderedList = False
    listTemplate = "unorderedlist"
    liChar = firstItem[len(prefix)][0] 
    regexString = "^" + prefix + "\\" + liChar + " "

    if liChar.isdigit():
        regexString = "^" + prefix + "[0-9]+\. "
        isOrderedList = True
        listTemplate = "orderedlist"

    result = ""
    subList = []
    for line in content:
        if re.search(regexString, line):
            if len(subList) > 0:
                result += parseLists(subList) + "\n"
                subList = []

            liTemplate = readTemplate("listitem")
            li = re.sub(regexString, "", line)
            result += liTemplate.replace("<CONTENT>", escapeAndSimpleFormat(li)) + "\n"
        else:
            subList.append(line)

    if len(subList) > 0:
        result += parseLists(subList)

    template = readTemplate(listTemplate)
    return template.replace("<CONTENT>", result.strip())

def parseExerciseMarkdown(basepath, content, outfile):
    with open(outfile, "w+") as out:
        processMarkdown(basepath, content, out, True)

def parseHostMarkdown(hostspath, host, ip, vulnx, content, outfile):
    with open(outfile, "w+") as out:
        para = readTemplate("vulnx")
        para = para.replace("<TITLE>", "Vulnerability Exploited:")
        para = para.replace("<CONTENT>", escapeAndSimpleFormat(vulnx))
        out.write(para + "\n")

        para = readTemplate("para_inline")
        para = para.replace("<TITLE>", "Sytem Vulnerable:")
        para = para.replace("<CONTENT>", escapeAndSimpleFormat(ip))
        out.write(para + "\n")

        basepath = os.path.join(hostspath, host)

        processMarkdown(basepath, content, out)

def processMarkdown(basepath, content, out, manualParagraphs = False):
    """Processes the markdown in the specified file.
    If manualParagraphs is True, the markdown section specifiers will be respected and treated as paragraphs.
    Otherwise, all section specifiers will be treated equally as latex sections and appear in the ToC.
    """
    buf = ""
    bufArr = []
    foundCodeStart = False
    foundListStart = False

    lineCounter = -1
    codeLineCounter = -1
    lastWasPlainText = -1
    for line in content:
        lineCounter += 1

        if line.startswith("```"):
            if not foundCodeStart:
                foundCodeStart = True
                codeLineCounter = 0
                highlights = parseHightlights(line)
                continue
            else:
                code = readTemplate("code")
                code = code.replace("<CODE>", buf.strip(" \n"))
                out.write(code + "\n")
                foundCodeStart = False
                codeLineCounter = -1
                buf = ""
                continue
        if foundCodeStart:
            codeLineCounter += 1 # please please note, line numbers are ONE based, not ZERO!
            if needsHighlight(codeLineCounter, highlights):
                buf += "**LINECHANGED@" + line + "@LINECHANGED**"+ "\n"
            else:
                buf += line + "\n"
            continue


        if re.search("^[0-9]+\. |^[*+\-] ", line.strip(" ")):
            if not foundListStart:
                foundListStart = True
                bufArr = []
            bufArr.append(line)
            continue

        if foundListStart:
            if line.lower().startswith("#"):
                lists = parseLists(bufArr)
                out.write(lists + "\n")
                foundListStart = False

        if line.lower().startswith("#"):
            if manualParagraphs:
                if line.lower().startswith("####"):
                    para = readTemplate("para_level4")
                elif line.lower().startswith("###"):
                    para = readTemplate("para_level3")
                elif line.lower().startswith("##"):
                    para = readTemplate("para_level2")
                else:
                    para = readTemplate("para_level1")
                para = para.replace("<CONTENT>", escapeAndSimpleFormat(line.strip(" #")))
            else:
                if ":" in line:
                    para = readTemplate("para_inline")
                    parts = line.strip(" #").split(":")
                    para = para.replace("<TITLE>", escapeAndSimpleFormat(parts[0].strip(" #")))
                    para = para.replace("<CONTENT>", escapeAndSimpleFormat(parts[1].strip(" #")))
                else:
                    para = readTemplate("para")
                    para = para.replace("<TITLE>", escapeAndSimpleFormat(line.strip(" #")))

            out.write(para + "\n")
            continue
        if line.lower().startswith("!["):
            if line.lower().startswith("![]"):
                image = readTemplate("image")
            else:
                image = readTemplate("image_ca[t]")
                capt = re.split("\[|\]", line)[1]
                image = image.replace("<CAPTION>", escapeAndSimpleFormat(capt.strip(" ")))

            path = re.split("\(|\)", line)[1]
            path = os.path.join(basepath, path.strip(" "))
            image = image.replace("<PATH>", path)
            out.write(image + "\n")
            continue
        
        if foundListStart:
            if line.strip(" ") == "":
                lists = parseLists(bufArr)
                out.write(lists + "\n")
                foundListStart = False
        elif not line.strip(" ") == "":
            if lineCounter >= 1 and lastWasPlainText + 2 == lineCounter and content[lineCounter - 1].strip(" ") == "":
                out.write("\\\\[0.5em]\n")
            lastWasPlainText = lineCounter
            out.write(escapeAndSimpleFormat(line.strip(" ")) + "\n")

def sortedNicely(l):
    """ Sorts the given iterable in the way that is expected.
 
    Required arguments:
    l -- The iterable to be sorted.
 
    """
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
    return sorted(l, key = alphanum_key)

def writeFiles(settings, hosts):
    machinecount = 0
    rootedcount = 0

    index = 64
    ipaddresses = []

    print "Preparing output files..."

    if not os.path.exists("out"):
        os.makedirs("out")

    curpath = os.path.dirname(os.path.abspath(__file__))
    shutil.copy(os.path.join(curpath, "packages.tex"), "./out/")
    shutil.copy(os.path.join(curpath, "templates", "intro.tex"), "./out/")

    for imgfile in glob.glob(os.path.join(curpath, "images", "*")):
        shutil.copy(imgfile, "./out/")

    with open("out/hosts.tex","w+") as outhosts:
        with open("out/settings.tex","w+") as out:
            out.write("\\renewcommand{\\fullname}{" + settings._fullname + "}\n")
            out.write("\\renewcommand{\\firstname}{" + settings._firstname + "}\n")
            out.write("\\renewcommand{\\osid}{" + settings._osid + "}\n")
            out.write("\\renewcommand{\\version}{" + settings._version + "}\n")
            out.write("\\renewcommand{\\email}{" + settings._email + "}\n")
    
            for host in hosts:
                machinecount += 1
                index += 1
        
                textfile = os.path.join(settings._hostspath, host, "report.md")
                genfile = os.path.join("out", host+".gen.tex")
                
                outhosts.write("\\input{"+genfile+"}\n")
                out.write("\\def\\got"+chr(index)+"{}\n")
    
                vulnx = ""
                ipaddress = ""
                foundStart = False
                with open(textfile) as f:
                    content = f.readlines()
                    # remove whitespace characters like `\n` at the end of each line
                    content = [x.strip("\n") for x in content]
                    linecount = 0           
                    for line in content:
                        linecount += 1
                        if not foundStart and line.startswith("---"):
                            foundStart = True
                            continue
                        if not foundStart:
                            continue
                        if  line.startswith("---"):
                            rest = content[linecount:]
                            parseHostMarkdown(settings._hostspath, host, ipaddress, vulnx, rest, genfile)
                            break
                        if line.lower().startswith("ip"):
                            ipaddress = getValue(line)
                            out.write("\\renewcommand{\\ip"+chr(index)+"}{" + ipaddress + "}\n")
                            ipaddresses.append(ipaddress)
                        if line.lower().startswith("tcpports"):
                            out.write("\\renewcommand{\\tcpports"+chr(index)+"}{" + getValue(line) + "}\n")
                        if line.lower().startswith("udpports"):
                            out.write("\\renewcommand{\\udpports"+chr(index)+"}{" + getValue(line) + "}\n")
                        if line.lower().startswith("vulnx"):
                            vulnx = getValue(line)
                            out.write("\\renewcommand{\\vulnx"+chr(index)+"}{" + escapeAndSimpleFormat(vulnx) + "}\n")
                        if line.lower().startswith("rooted"):
                            rootedcount += 1

                textfile = os.path.join(settings._hostspath, host, "local.md")
                genfile = os.path.join("out", host+"_local.gen.tex")
                vulnx = ""
                foundStart = False
                if os.path.exists(textfile):
                    outhosts.write("\\input{"+genfile+"}\n")
                    with open(textfile) as f:
                        content = f.readlines()
                        # remove whitespace characters like `\n` at the end of each line
                        content = [x.strip("\n") for x in content]
                        linecount = 0           
                        for line in content:
                            linecount += 1
                            if not foundStart and line.startswith("---"):
                                foundStart = True
                                continue
                            if not foundStart:
                                continue
                            if  line.startswith("---"):
                                rest = content[linecount:]
                                parseHostMarkdown(settings._hostspath, host, ipaddress, vulnx, rest, genfile)
                                break
                            if line.lower().startswith("vulnx"):
                                vulnx = getValue(line)

            if settings._exercisespath:
                shutil.copy(os.path.join(curpath, "templates", "exercises.tex"), "./out/")
                outhosts.write("\\input{out/exercises.tex}\n")


                fileList = []
                for root, dirs, files in os.walk(settings._exercisespath):
                    for file in files:
                        if file.endswith("report.md"):
                            textfile = os.path.join(root, file)
                            fileList.append(textfile)

                fileList = sortedNicely(fileList)
                for textfile in fileList:
                    escapedName = os.path.relpath(textfile, settings._exercisespath)
                    escapedName = escapedName.replace("/", "_")
                    escapedName = escapedName.replace(".", "_")

                    genfile = os.path.join("out", escapedName+".gen.tex")
                    foundStart = False
                    outhosts.write("\\input{"+genfile+"}\n")
                    with open(textfile) as f:
                        content = f.readlines()
                        # remove whitespace characters like `\n` at the end of each line
                        content = [x.strip("\n") for x in content]
                        parseExerciseMarkdown(os.path.dirname(textfile), content, genfile)
            
            out.write("\\renewcommand{\\machinecount}{" + str(machinecount) + "}\n")
            out.write("\\renewcommand{\\rootedcount}{" + str(rootedcount) + "}\n")
            out.write("\\renewcommand{\\ipaddresses}{" + (", ".join(ipaddresses)) + "}\n")

def executePdflatex(outputfile):
    directory = os.path.dirname(outputfile)
    filename = os.path.basename(outputfile)
    jobname = os.path.splitext(filename)[0]
    curpath = os.path.dirname(os.path.abspath(__file__))
    maindocument = os.path.join(curpath, "maindocument.tex")

    print "Generating PDF..."

    args = ['pdflatex', 
            '--interaction=batchmode', 
            #'-output-directory='+directory, 
            '-jobname='+jobname,
            maindocument]
    print(args)
    subprocess.call(args)
    print "See maindocument.log for more information."

def main():
    """
    """
    if len(sys.argv) == 1:
        print "Usage:"
        print "  generate.py <settings.md> [options]"
        print
        print "Options:"
        print "  --pdf-only      Only generate the pdf from existing tex files (useful for manual finetuning)"
    else:
        settings = Settings(sys.argv[1])

        pdfonly = (len(sys.argv) > 2) and (sys.argv[2].lower() == "--pdf-only")

        if not pdfonly:
            writeFiles(settings, settings._hosts)

        executePdflatex(settings._outputfile)

if __name__ == "__main__":
    main()
