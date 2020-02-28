# Writing my OSCP report in Markdown

The basic idea is that every host gets a own folder (just copy the example).
While doing the machine the documentation goes into the markdown file.

Not so much as a template for what the report should contain, but for not
being bothered by fiddling with layout thingies _especially_ in Word.

## Documenting a new host for the report

1. Create a subfolder with the name of the machine
2. Create a host.md
3. Give a header like:
```
---
hostname: 'example'
ip: '10.11.1.1'
tcpports: '1, 2, 3, 4'
udpports: '5, 6, 7, 8'
vulnx: 'SomeWebService <= 1.3.3 Directory Traversal RCE (CVE-2001-10000)
severity: 'Critical'
rooted: true
---
```
4. Write your report, using headers "##", code blocks and images. 
(TODO: hyperlinks, bold/italic/red, ...)
5. Update your user info in the settings.md in the root of the project.
6. Add the new machine to hosts in the settings.md.
7. Run generate.py
8. Run pdflatex maindocument.tex
9. Check your pdf!

## Notes
Using different headers, e.g. "#", "##" and "###", does results in 
different sub sections. It all will be on the same level. My report
did not require subsections

Using a ":" in the header, makes a difference in layout. With ":" the
content will directly follow the header. Not using a ":", will put the
following content below the header.

## Todo
Add support for hyperlinks, bold/italic and RED markings in code blocks!

Supports up to 5 machines now. Should be using loops in LaTeX...

Update the fonts to match the OSCP report.

## How does it work?
This project is based on the LaTeX to PDF from: https://github.com/ucki/zauberfeder/

LaTex is not really my friend, so I decided to use markdown and generate LaTeX files
from that in python. Also updated the style to beter match the OSCP template.

## Install Required Packages
```
apt install pandoc
apt install texlive-latex-base texlive-fonts-recommended texlive-fonts-extra texlive-latex-extra

tlmgr init-usertree
tlmgr install pdftexcmds
tlmgr install infwarerr
tlmgr install letltxmacro
tlmgr install booktabs
tlmgr install fancyvrb
tlmgr install grffile

tlmgr install titling
tlmgr install anyfontsize
tlmgr install tlenc
```
Note: some packages could be obsolete or missing.

## Real usage
I did not use it for my exam, but found it a real hell to use Word to create a 
report. I hope this helps any PWK student, please give me a heads up if this
worked for you!
