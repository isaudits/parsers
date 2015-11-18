<?xml version="1.0" encoding="utf-8"?>
<!-- =========================================================================
     Extracts patch status findings (Nessus ID 66334) from a Nessus scan report
     XML File
     ============================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:common="http://exslt.org/common" exclude-result-prefixes="common">
<xsl:output method="html" encoding="UTF-8" indent="yes"/>
<!-- Vulnerabilities reference list -->
<xsl:param name="vulnerabilities" select="'Vulnerabilities.xml'"/>
<xsl:variable name="Vulnerabilities" select="document($vulnerabilities)/NessusVulnerabilities"/>
<!-- Hosts reference list -->
<xsl:param name="hosts" select="'Hosts.xml'"/>
<xsl:variable name="Hosts" select="document($hosts)/hosts"/>
<!-- Nessus vulnerabilities -->
<xsl:variable name="Nessus" select="/NessusClientData_v2"/>
<!-- Line feeds -->
<xsl:variable name="new_line" select="'&#xa;'"/>
	<xsl:template match="/">
		<html>
			<head>
				<title>
					Add something cool here!
				</title>
			</head>			
			<body>
				<table border="1" frame="box" rules="all">
					<tr class="head">
						<th title="IP">IP</th>
						<th title="Hostname">Hostname</th>
						<th title="Detail">Details</th>
					</tr>	
					<xsl:for-each select="$Nessus/Report/ReportHost">
						<xsl:sort select="substring-after(substring-after(substring-after(@name,'.'),'.'),'.')" data-type="number"/>
						<xsl:variable name="ReportHost" select="@name"/>
						<xsl:variable name="HostName" select="HostProperties/tag[@name='host-fqdn']"/>
						
						<tr>
							<td class="ip" valign="top">
								<xsl:value-of select="$ReportHost"/>
							</td>
							<td class="hostname" valign="top">
								<xsl:value-of select="$HostName"/>
							</td>
							<td class="patchDetail">
								<xsl:variable name="Vulnerability" select="ReportItem[@pluginID=66334]"/>
								<xsl:variable name="Detail" select="ReportItem[@pluginID=66334]/plugin_output"/>
								<xsl:if test="$Vulnerability">
									<pre><xsl:value-of select="$Detail"/></pre>
								</xsl:if>
								
							</td>	
						</tr>
					</xsl:for-each>
				</table>				  
				
			</body>
		</html>
	</xsl:template>
</xsl:stylesheet>