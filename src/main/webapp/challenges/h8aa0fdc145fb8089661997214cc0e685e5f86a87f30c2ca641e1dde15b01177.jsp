<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"
	language="java" import="utils.*, dbProcs.Getter" errorPage=""%>
<%@ page import="java.util.Locale, java.util.ResourceBundle"%>
<%
/**
 * Insecure Cryptographic Storage Challenge 2
 * <br/><br/>
 * This file is part of the Security Shepherd Project.
 * 
 * The Security Shepherd project is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.<br/>
 * 
 * The Security Shepherd project is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.<br/>
 * 
 * You should have received a copy of the GNU General Public License
 * along with the Security Shepherd project.  If not, see <http://www.gnu.org/licenses/>. 
 *
 * @author Mark Denihan
 */

String levelName = "Insecure Cryptographic Storage Challenge 2";
String levelHash = "h8aa0fdc145fb8089661997214cc0e685e5f86a87f30c2ca641e1dde15b01177";
 
 //Translation Stuff
 Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
 ResourceBundle bundle = ResourceBundle.getBundle("i18n.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
 //Used more than once translations
 String i18nLevelName = bundle.getString("insecureCryptoStorage.2.challengename");
 ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " Accessed");
 if (request.getSession() != null)
 {
 	HttpSession ses = request.getSession();
 	//Getting CSRF Token from client
 	Cookie tokenCookie = null;
 	try
 	{
 		tokenCookie = Validate.getToken(request.getCookies());
 	}
 	catch(Exception htmlE)
 	{
 		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName +".jsp: tokenCookie Error:" + htmlE.toString());
 	}
 	// validateSession ensures a valid session, and valid role credentials
 	// If tokenCookie == null, then the page is not going to continue loading
 	if (Validate.validateSession(ses) && tokenCookie != null)
 	{
 		ShepherdLogManager.logEvent(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"), levelName + " has been accessed by " + ses.getAttribute("userName").toString(), ses.getAttribute("userName"));
		//Key check, done on the server so the key is never sent to the browser
		String resultKeyAttempt = request.getParameter("resultKeyAttempt");
		if ("POST".equalsIgnoreCase(request.getMethod()) && resultKeyAttempt != null)
		{
			String levelResult = Getter.getModuleResultFromHash(getServletContext().getRealPath(""), levelHash);
			if (resultKeyAttempt.equals(levelResult))
				out.print("<p>Yeah, that's correct</p>");
			else
				out.print("<p>No, that's not correct</p>");
			return;
		}
%>

<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<title>Security Shepherd - <%= i18nLevelName %></title>
<link href="../css/lessonCss/theCss.css" rel="stylesheet"
	type="text/css" media="screen" />

</head>
<body>
	<script type="text/javascript" src="../js/jquery.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard.min.js"></script>
	<script type="text/javascript" src="../js/clipboard-js/tooltips.js"></script>
	<script type="text/javascript"
		src="../js/clipboard-js/clipboard-events.js"></script>
	<div id="contentDiv">
		<h2 class="title"><%= i18nLevelName %></h2>
		<p>
			<%= bundle.getString("insecureCryptoStorage.2.whatToDo") %>
			<br /> <br />
		<form id="leForm" action="javascript:;">
			<table>
				<tr>
					<td><input type="text" id="resultKeyAttempt"
						style="width: 300px;" /></><input type="submit"
						value="<%= bundle.getString("insecureCryptoStorage.2.checkKey") %>" />
					</td>
				</tr>
			</table>
		</form>
		<br /> <br />
		<div id="resultDiv"></div>
		</p>
	</div>
	<script>			
		$("#leForm").submit(function(){
			// The key is checked on the server. No key material is sent to the browser
			var input = $("#resultKeyAttempt").val();
			$("#resultDiv").hide("fast", function(){
				var ajaxCall = $.ajax({
					type: "POST",
					url: "h8aa0fdc145fb8089661997214cc0e685e5f86a87f30c2ca641e1dde15b01177.jsp",
					data: {
						resultKeyAttempt: input
					},
					async: false
				});
				$('#resultDiv').html(ajaxCall.responseText);
				$("#resultDiv").show("slow");
			});
			// <%= bundle.getString("insecureCryptoStorage.2.commentedCode.4") %>
			/*
			$("#resultDiv").hide("fast", function(){
					$('#resultDiv').html("Encrypted Output: " + output);
				$("#resultDiv").show("slow");
			});
			*/
		});
		</script>
	<% if(Analytics.googleAnalyticsOn) { %><%= Analytics.googleAnalyticsScript %>
	<% } %>
</body>
</html>
<%
	}
	else
	{
		response.sendRedirect("../loggedOutSheep.html");
	}
}
else
{
	response.sendRedirect("../loggedOutSheep.html");
}
%>
