<?xml version="1.0" encoding="utf-8"?>
<!-- ==========================================================================
     Extracts patch status findings (Nessus ID 66334) from a Nessus scan report
     XML File
	 ========================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:cm="http://www.nessus.org/cm" xmlns:common="http://exslt.org/common" exclude-result-prefixes="common">
<xsl:output method="html" encoding="UTF-8" indent="yes"/>
<!-- Nessus vulnerabilities -->
<xsl:variable name="Nessus" select="/NessusClientData_v2"/>
<!-- Line feeds -->
<xsl:variable name="new_line" select="'&#xa;'"/>
	<xsl:template match="*">
		<html>
			<head>
				<title>
					Nessus compliance report
				</title>
			</head>
			<style>
				body {
				    margin: 0;
				    padding: 0;
				    text-align: center;
				    font-family: Calibri, Helvetica, sans-serif;
				    font-size: 10pt;
				    background-color: #ffffff;
				    color: #1f1f1f;
				}
				#container {
				    margin: 16px auto;
				    padding: 0;
				    width: 90%;
				    text-align: left;
				}
				#banner {
				    margin 0;
				    padding 0;
				    background-color: #f1f1f1;
				    border: 1px solid #1f1f1f;
				    text-align: center;
				}
				#banner h1 {
				    font-size: 2.75em;
				    line-height: 1.5;
				    color: #e40000;
				    margin: 0;
				    padding: 0;
				}
				#banner h2 {
				    font-size: 1.5em;
				    line-height: 1.25;
				    margin: 0;
				    padding: 0;
				    color: #000000;
				}
				p {
				    margin: 0 0 4px 0;
				    padding: 0;
				}
				h1 {
				    margin: 24px 0 0 0;
				    padding: 0;
				    font-size: 1.5em;
				}
				h2 {
				    margin: 12px 0 0 0;
				    padding: 0;
				    font-size: 1.25em;
				    color: #e40000;
				}
				pre {
					white-space: pre-wrap;       /* CSS 3 */
				    white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
				    white-space: -pre-wrap;      /* Opera 4-6 */
				    white-space: -o-pre-wrap;    /* Opera 7 */
				    word-wrap: break-word;       /* Internet Explorer 5.5+ */
				}
				table { border-collapse: collapse; table-layout: fixed; width: 100%; }
				table, td, th { border: 1px solid #000000; vertical-align: top; }
				th { text-align: center; background-color: #f1f1f1; }
				td { padding: 0 4px 0 4px; word-wrap:break-word; }
			</style>
						
			<body>
				<div id="container">
					<div id="banner">
						<h1>Compliance check summary report</h1>
					</div>

					<xsl:for-each select="$Nessus/Report/ReportHost">
						<xsl:sort select="substring-after(substring-after(substring-after(@name,'.'),'.'),'.')" data-type="number"/>
						<xsl:variable name="ReportHost" select="@name"/>
						<xsl:variable name="HostName" select="HostProperties/tag[@name='host-fqdn']"/>
						<h2>
							<xsl:value-of select="$ReportHost"/>
						 	<xsl:if test="$HostName">
						 		- <xsl:value-of select="$HostName"/>
						 	</xsl:if>
						</h2>
						<table>
							<tr>
								<th id="check" width="50%" max-width="100px">Check</th>
								<th id="result" width="60px">Result</th>
								<th id="policyvalue">Policy Value</th>
								<th id="actualvalue">Actual Value</th>
							</tr>	
							<xsl:for-each select="ReportItem">
								<xsl:sort select="cm:compliance-result"/>
								<xsl:variable name="IsCompliance" select="compliance='true'"/>
								<xsl:variable name="Result" select="cm:compliance-result"/>

								<xsl:if test="$IsCompliance and $Result!='ERROR'">
									<xsl:variable name="Check" select="cm:compliance-check-name"/>
									<xsl:variable name="PolicyValue" select="cm:compliance-policy-value"/>
									<xsl:variable name="ActualValue" select="cm:compliance-actual-value"/>

									<xsl:variable name="Output" select="cm:compliance-output"/>
									<xsl:variable name="Info" select="cm:compliance-info"/>
									<xsl:variable name="Reference" select="cm:compliance-reference"/>
									<xsl:variable name="Solution" select="cm:compliance-solution"/>
									
									<xsl:variable name="Description" select="description"/>
									<tr>
										<td name="check">
											<xsl:value-of select="$Check"/>
										</td>
										<td name="result">
											<xsl:value-of select="$Result"/>
										</td>
										<td name="output">
											<xsl:value-of select="$PolicyValue"/>
										</td>
										<td name="info">
											<xsl:value-of select="$ActualValue"/>
										</td>
									</tr>
								</xsl:if>
							</xsl:for-each>
						</table>
					</xsl:for-each>
				</div>				  
			</body>
		</html>
	</xsl:template>
</xsl:stylesheet>