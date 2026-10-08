package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * SQL Injection Stored Procedure Challenge - Does not use user specific keys <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class SqlInjectionStoredProcedure extends HttpServlet {

  // SQL Challenge One
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SqlInjectionStoredProcedure.class);
  // ASVS 2.2.1: positive (allow list) validation of the email address the search expects
  private static final Pattern EMAIL_ALLOW_LIST =
      Pattern.compile("^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,63}\\.[A-Za-z]{2,24}$");
  private static final int MAX_ADDRESS_LENGTH = 128; // customerAddress / findUser(VARCHAR(128))
  private static String levelName = "SQL Injection Stored Procedure Challenge";
  public static String levelHash =
      "7edcbc1418f11347167dabb69fcb54137960405da2f7a90a0684f86c4d45a2e7";

  // private static String levelResult = ""; // Stored in Vulnerable DB. Not user Specific

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle("i18n.servlets.challenges.sqli.sqliStoreProcedure", locale);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();

      try {
        String userIdentity = request.getParameter("userIdentity");
        log.debug("User Submitted - " + userIdentity);
        String ApplicationRoot = getServletContext().getRealPath("");

        log.debug("Getting Connection to Database");
        // ASVS 2.2.1 / 2.2.2: validate on the server before the value reaches the database
        if (userIdentity == null
            || userIdentity.length() > MAX_ADDRESS_LENGTH
            || !EMAIL_ALLOW_LIST.matcher(userIdentity).matches()) {
          log.debug("Rejected input that is not a valid email address");
          out.write("<p>" + bundle.getString("response.noResults") + "</p>");
          return;
        }
        Connection conn =
            Database.getChallengeConnection(ApplicationRoot, "SqlChallengeStoredProc");
        // ASVS 1.2.4: the stored procedure is called with a bound parameter, never concatenated
        CallableStatement stmt = conn.prepareCall("{call findUser(?)}");
        stmt.setString(1, userIdentity);
        ResultSet resultSet = stmt.executeQuery();

        int i = 0;
        htmlOutput = "<h2 class='title'>" + bundle.getString("response.searchResults") + "</h2>";
        // ASVS 14.2.6 / 8.2.3: only the fields the lookup needs are returned. The internal customer
        // comment is never sent to the client
        htmlOutput +=
            "<table><tr><th>"
                + bundle.getString("response.table.name")
                + "</th><th>"
                + bundle.getString("response.table.address")
                + "</th></tr>";

        log.debug("Opening Result Set from query");
        while (resultSet.next()) {
          log.debug("Adding Customer " + resultSet.getString(2));
          htmlOutput +=
              "<tr><td>"
                  + Encode.forHtml(resultSet.getString(2))
                  + "</td><td>"
                  + Encode.forHtml(resultSet.getString(3))
                  + "</td></tr>";
          i++;
        }
        conn.close();
        htmlOutput += "</table>";
        if (i == 0) {
          htmlOutput = "<p>" + bundle.getString("response.noResults") + "</p>";
        }
      } catch (SQLException e) {
        // ASVS 16.5.1: details are logged, the client only gets a generic message
        log.error(levelName + " SQL Error - " + e.toString());
        htmlOutput = "<p>" + errors.getString("error.funky") + "</p>";
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
      log.debug("Outputting HTML");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
