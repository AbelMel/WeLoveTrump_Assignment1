/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package validate;

import java.sql.PreparedStatement;
import dbconnection.DBConnect;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.RequestDispatcher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author stephen
 */
public class ValidateLogin extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        String user=request.getParameter("username").trim();
        String pass=request.getParameter("password").trim();
        
        try
             {
                 Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
                    if(con!=null && !con.isClosed())
                               {
                                   ResultSet rs=null;
                                   PreparedStatement pstmt = con.prepareStatement( "SELECT * FROM users WHERE username = ? AND password = ?" );
                                   pstmt.setString(1, user);
                                   pstmt.setString(2, pass);
                                   rs = pstmt.executeQuery();
                                   if(rs != null && rs.next()){
                                        HttpSession session=request.getSession();
                                        session.setAttribute("userid", rs.getString("id"));
                                        session.setAttribute("user", rs.getString("username"));
                                        session.setAttribute("isLoggedIn", "1");
                                        Cookie privilege=new Cookie("privilege", getMD5(user));
                                        response.addCookie(privilege);
                                        response.sendRedirect("members.jsp");
                                   }
                                   else{
                                        request.setAttribute("errMsg", "Username Or Password are incorrect");
                                        RequestDispatcher rd = request.getRequestDispatcher("/login.jsp");
                                        rd.forward(request, response); 
                                   }
                                   
                               }
             }
               catch(Exception ex)
                {
                           response.sendRedirect("login.jsp");
                 }
        
        
    }
    
    private String getMD5(String user) {

        MessageDigest mdAlgorithm = null;
        try {
            mdAlgorithm = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ValidateLogin.class.getName()).log(Level.SEVERE, null, ex);
        }
        mdAlgorithm.update(user.getBytes());

        byte[] digest = mdAlgorithm.digest();
        StringBuffer hexString = new StringBuffer(2 * digest.length);

        for (int i = 0; i < digest.length; i++) {
            user = Integer.toHexString(0xFF & digest[i]);

            if (user.length() == 1) {
                user = "0" + user;
            }

            hexString.append(user);
        }

return hexString.toString();

        
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
