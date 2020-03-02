#!/usr/bin/env python

hostsPath = "./hosts/"
templatesPath = "./templates/"

import os
import re
import subprocess
import HTMLParser

def getValue(line):
    index = line.index(":")
    return line[index+1:].strip(" '\"")

def readTemplate(name):
    templatefile = os.path.join(templatesPath, name + ".tex")
    with open(templatefile) as f:
        content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        content = [x.strip("\n") for x in content]
        return "\n".join(content)

class Settings:
    def __init__(self, textfile):
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

                if line.lower().startswith("fullname"):
                    self._fullname = getValue(line)
                elif line.lower().startswith("firstname"):
                    self._firstname = getValue(line)
                elif line.lower().startswith("osid"):
                    self._osid = getValue(line)
                elif line.lower().startswith("version"):
                    self._version = getValue(line)
                elif line.lower().startswith("email"):
                    self._email = getValue(line)
                elif line.lower().startswith("hosts"):
                    self._hosts = [x.strip() for x in getValue(line).split(",")]

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

def escapeLatex(line):
    html = HTMLParser.HTMLParser()
    line = html.unescape(line)
    # \& \% \$ \# \_ \{ \}
    line = line.replace("&", "\\&")
    line = line.replace("%", "\\%")
    line = line.replace("$", "\\$")
    line = line.replace("#", "\\#")
    line = line.replace("_", "\\_")
    line = line.replace("{", "\\{")
    line = line.replace("}", "\\}")

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
            result += liTemplate.replace("<CONTENT>", escapeLatex(li)) + "\n"
        else:
            subList.append(line)

    if len(subList) > 0:
        result += parseLists(subList)

    template = readTemplate(listTemplate)
    return template.replace("<CONTENT>", result.strip())

def parseMarkdown(host, ip, vulnx, content, outfile):
    buf = ""
    bufArr = []
    foundCodeStart = False
    foundListStart = False
    with open(outfile, "w+") as out:
        para = readTemplate("vulnx")
        para = para.replace("<TITLE>", "Vulnerability Exploited:")
        para = para.replace("<CONTENT>", escapeLatex(vulnx))
        out.write(para + "\n")

        para = readTemplate("para_inline")
        para = para.replace("<TITLE>", "Sytem Vulnerable:")
        para = para.replace("<CONTENT>", escapeLatex(ip))
        out.write(para + "\n")

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
                if ":" in line:
                    para = readTemplate("para_inline")
                    parts = line.strip(" #").split(":")
                    para = para.replace("<TITLE>", escapeLatex(parts[0].strip(" #")))
                    para = para.replace("<CONTENT>", escapeLatex(parts[1].strip(" #")))
                else:
                    para = readTemplate("para")
                    para = para.replace("<TITLE>", escapeLatex(line.strip(" #")))

                out.write(para + "\n")
                continue
            if line.lower().startswith("!["):
                if line.lower().startswith("![]"):
                    image = readTemplate("image")
                else:
                    image = readTemplate("image_ca[t]")
                    capt = re.split("\[|\]", line)[1]
                    image = image.replace("<CAPTION>", escapeLatex(capt.strip(" ")))

                path = re.split("\(|\)", line)[1]
                path = os.path.join(hostsPath, host, path.strip(" "))
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
                out.write(escapeLatex(line.strip(" ")) + "\n")


def writeFiles(settings, hosts):
    machinecount = 0
    rootedcount = 0

    index = 64
    ipaddresses = []

    if not os.path.exists("out"):
        os.makedirs("out")

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
        
                textfile = os.path.join(hostsPath, host, "host.md")
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
                            parseMarkdown(host, ipaddress, vulnx, rest, genfile)
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
                            out.write("\\renewcommand{\\vulnx"+chr(index)+"}{" + vulnx + "}\n")
                        if line.lower().startswith("rooted"):
                            rootedcount += 1

                textfile = os.path.join(hostsPath, host, "local.md")
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
                                parseMarkdown(host, ipaddress, vulnx, rest, genfile)
                                break
                            if line.lower().startswith("vulnx"):
                                vulnx = getValue(line)
        
            out.write("\\renewcommand{\\machinecount}{" + str(machinecount) + "}\n")
            out.write("\\renewcommand{\\rootedcount}{" + str(rootedcount) + "}\n")
            out.write("\\renewcommand{\\ipaddresses}{" + (", ".join(ipaddresses)) + "}\n")

def executePdflatex():
    subprocess.call(['pdflatex', '--interaction=batchmode', 'maindocument.tex'])
    print "See maindocument.log for more information."

def main():
    """
    """
    settings = Settings("settings.md")

    writeFiles(settings, settings._hosts)
    executePdflatex()


if __name__ == "__main__":
    main()
