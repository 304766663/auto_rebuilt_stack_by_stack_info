#!/usr/bin/python
# -*- coding: UTF-8 -*-
import re

class StackAnalyzer:
	m_len = 0
	m_Ebp = ()
	m_RetAddr = ()
	m_PdbStr = ()

	def __init__(self):
		self.m_file = open("result.txt", "w")

	def __del__(self):
		self.m_file.close()

	def readFileLines(self):
		filePath = raw_input("请输入要分析的windbg堆栈文件(by dds)：");
		fo = open(filePath, "r+")
		lines = fo.readlines(0xfffff)
		fo.close()
		return lines

	def readStackInfo(self):
		lines = self.readFileLines()
		for line in lines:
			regexResult = re.search(r'\s*(\w{8})\s*(\w{8})\s*(.*)\s*', line, re.M|re.I)
			if regexResult:
				self.m_Ebp = (regexResult.group(1),) + self.m_Ebp
				self.m_RetAddr = (regexResult.group(2),) + self.m_RetAddr
				self.m_PdbStr = (regexResult.group(3),) + self.m_PdbStr

		self.m_len = len(self.m_Ebp)

	def figureAndPrint(self, indexNow, traceData = ""):
		traceData = self.m_Ebp[indexNow] + "  " + self.m_RetAddr[indexNow] + "  " + self.m_PdbStr[indexNow] + "\n" + traceData
		if indexNow + 2 > self.m_len:
			self.m_file.write(traceData + "\n\n")
			return

		findMatch = False
		for indexSearch in range(indexNow + 2, self.m_len - 1):
			if self.m_Ebp[indexNow + 1] == self.m_RetAddr[indexSearch + 1]:
				self.figureAndPrint(indexSearch, traceData)
				findMatch = True

		if not findMatch:
			self.m_file.write(traceData + "\n\n")

	def doAnalyze(self):
		self.readStackInfo()
		rootStackIndex = ()

		root = raw_input("请输入底层堆栈（1 ntdll!_RtlUserThreadStart 2 tmainCRTStartup）：");
		rootStr = ""
		if root == '1':
			rootStr = "ntdll!_RtlUserThreadStart"
			print '1'
		elif root == '2':
			rootStr = "tmainCRTStartup"
			print '2'
		print rootStr

		for index in range(self.m_len):
			strData = re.search(r'.*' + re.escape(rootStr) + '.*', self.m_PdbStr[index], re.M|re.I)
			if strData:
				for indx in rootStackIndex:
					if self.m_Ebp[indx + 1] == self.m_RetAddr[index + 1]:
						break
				else:
					self.figureAndPrint(index)

analyzer = StackAnalyzer()
analyzer.doAnalyze()
print "==== 分析完成，结果请查看 result.txt ===="