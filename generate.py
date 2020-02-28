#!/usr/bin/env python

hostsPath = "./hosts/"
templatesPath = "./templates/"

import os
import re
import subprocess

def getValue(line):
    index = line.index(":")
    return line[index+1:].strip(" '\"")

def readTemplate(name):
    templatefile = os.path.join(templatesPath, name + ".tex")
    with open(templatefile) as f:
        content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        content = [x.strip() for x in content]
        return "\n".join(content)

class Settings:
    def __init__(self, textfile):
        with open(textfile) as f:
            content = f.readlines()
            # remove whitespace characters like `\n` at the end of each line
            content = [x.strip() for x in content]

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

def parseMarkdown(host, ip, vulnx, content):
    outfile = os.path.join(hostsPath, host, "host.gen.tex")
    buf = ""
    foundCodeStart = False
    with open(outfile, "w+") as out:
        para = readTemplate("vulnx")
        para = para.replace("<TITLE>", "Vulnerability Exploited:")
        para = para.replace("<CONTENT>", vulnx)
        out.write(para + "\n")

        para = readTemplate("para_inline")
        para = para.replace("<TITLE>", "Sytem Vulnerable:")
        para = para.replace("<CONTENT>", ip)
        out.write(para + "\n")

        lineCounter = -1
        lastWasPlainText = -1
        for line in content:
            lineCounter += 1

            if line.startswith("```"):
                if not foundCodeStart:
                    foundCodeStart = True
                    continue
                else:
                    code = readTemplate("code")
                    code = code.replace("<CODE>", buf.strip(" \n"))
                    out.write(code + "\n")
                    foundCodeStart = False
                    buf = ""
                    continue
            if foundCodeStart:
                buf += line + "\n"
                continue
            if line.lower().startswith("#"):
                if ":" in line:
                    para = readTemplate("para_inline")
                    parts = line.strip(" #").split(":")
                    para = para.replace("<TITLE>", parts[0].strip(" #"))
                    para = para.replace("<CONTENT>", parts[1].strip(" #"))
                else:
                    para = readTemplate("para")
                    para = para.replace("<TITLE>", line.strip(" #"))

                out.write(para + "\n")
                continue
            if line.lower().startswith("!["):
                if line.lower().startswith("![]"):
                    image = readTemplate("image")
                else:
                    image = readTemplate("image_ca[t]")
                    capt = re.split("\[|\]", line)[1]
                    image = image.replace("<CAPTION>", capt.strip(" "))

                path = re.split("\(|\)", line)[1]
                path = os.path.join(hostsPath, host, path.strip(" "))
                image = image.replace("<PATH>", path)
                out.write(image + "\n")
                continue
            
            if not line.strip(" ") == "":
                if lineCounter >= 1 and lastWasPlainText + 2 == lineCounter and content[lineCounter - 1].strip(" ") == "":
                    out.write("\\\\[0.5em]\n")
                lastWasPlainText = lineCounter
                out.write(line.strip(" ") + "\n")


def writeFiles(settings, hosts):
    machinecount = 0
    rootedcount = 0

    index = 64
    ipaddresses = []

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
                genfile = os.path.join(hostsPath, host, "host.gen.tex")
                
                outhosts.write("\\input{"+genfile+"}\n")
                out.write("\\def\\got"+chr(index)+"{}\n")
    
                vulnx = ""
                ipaddress = ""
                foundStart = False
                with open(textfile) as f:
                    content = f.readlines()
                    # remove whitespace characters like `\n` at the end of each line
                    content = [x.strip() for x in content]
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
                            parseMarkdown(host, ipaddress, vulnx, rest)
                            break
                        if line.lower().startswith("ip"):
                            ipaddress = getValue(line)
                            out.write("\\renewcommand{\\ip"+chr(index)+"}{" + ipaddress + "}\n")
                            ipaddresses.append(ipaddress)
                        #if line.lower().startswith("hostname"):
                        #    print line
                        if line.lower().startswith("tcpports"):
                            out.write("\\renewcommand{\\tcpports"+chr(index)+"}{" + getValue(line) + "}\n")
                        if line.lower().startswith("udpports"):
                            out.write("\\renewcommand{\\udpports"+chr(index)+"}{" + getValue(line) + "}\n")
                        if line.lower().startswith("vulnx"):
                            vulnx = getValue(line)
                            out.write("\\renewcommand{\\vulnx"+chr(index)+"}{" + vulnx + "}\n")
                        #if line.lower().startswith("severity"):
                        #    print line
                        if line.lower().startswith("rooted"):
                            rootedcount += 1
    
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
