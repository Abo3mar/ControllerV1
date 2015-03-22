
    package JDBC;
   //import com.mysql.jdbc.PreparedStatement;
import java.sql.*;
    //import com.mysql.*;
    //import org.gjt.mm.mysql.*;
public class jdbcQuery {
	private multi_Type RULES = null;
	private Connection myConnection;
    public jdbcQuery(){}
    public multi_Type Connect(long mac){ 
    	try{
    		// The newInstance() call is a work around for some
    		// broken Java implementations            
    		Class.forName("com.mysql.jdbc.Driver").newInstance();
    	} catch (Exception ex) {
    		System.out.println("SQLException: class.forname:" + ex.getMessage());
    	}
   
    	//modify these as needed
    	String rootUsername = "root";
    	String rootPassword = "";
    	String connectionDatabase = "jdbc:mysql://localhost:3306/macRulesSchema";
    	
    	try {
    		//attempt to connect to mysql database
    		myConnection = DriverManager.getConnection(connectionDatabase, rootUsername, rootPassword);                    
    	} catch (SQLException ex) {
    		
    		//handel error here
    		System.out.println("SQLException: Driver skrewup" + ex.getMessage());
    		System.out.println("SQLState: " + ex.getSQLState());
    		System.out.println("VendorError: " + ex.getErrorCode());
                                    }
    		boolean advance = false;                
    		PreparedStatement update = null;
    		PreparedStatement check = null;
    		ResultSet resp = null;
    		long x = 0;
    		String checkMAC = "SELECT mac FROM macRulesTable WHERE mac = ?";
    		String inputMac = "INSERT into macRulesTable (mac) Value (?)";
    		
    		try {
    		
    			check = myConnection.prepareStatement(checkMAC);
    			check.setLong(1, mac);
    			resp = check.executeQuery();
    			/******
    			 * checking to see if mac is already in the database
    			 */
    			while(resp.next()){
    				x=resp.getLong("mac");
    			}
    				System.out.println(x);
    			if(x == mac){
    				advance = true;
    			}else{
    				advance = false;
    			}
    				System.out.println(advance);
    			
    		} catch (SQLException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		}
    		
    		/****
    		 * if MAC is not in database, install MAC. 
    		 */
    		if(!advance){
    			try{
    				update = myConnection.prepareStatement(inputMac);
    				update.setLong(1,mac);
    				update.executeUpdate();
        		} catch (Exception exc) {//handle exceptions here
        			System.out.println(" Installing mac failed "+ exc.getMessage());
        			exc.printStackTrace();
                } finally { //cleanup    	
                	if (update != null) {
                		// update.close();
                	}
                }
    		}
    		
    		/***
    		 * Once MAC is installed or if it is already installed
    		 * return the associated Rules.	
    		 */
                   
    		PreparedStatement myStatement = null;
    		ResultSet myResultSet = null;
    		//String dbTable = "macRulesTable";
    		String SQL = "(SELECT block, user_total, total_all, start_time, stop_time, bw_limit,current_user_usage, current_total_usage, terminal_name, total_bw, total_data FROM macRulesTable WHERE mac = ?)";
    		try {
    				myStatement = myConnection.prepareStatement(SQL);//generate statement based on established connection
    				myStatement.setLong(1,mac);
    				myResultSet = (myStatement.executeQuery());
    				/***
    				 * Store MAC rules in multi_Type object to be returned to for 
    				 * flow decisions to be determined upon.
    				 */
    				while (myResultSet.next()) {
    					RULES = new multi_Type(myResultSet.getBoolean("block"),
    							myResultSet.getLong("user_total"),
    							myResultSet.getLong("total_all"), 
    							myResultSet.getTime("start_time"),
    							myResultSet.getTime("stop_time"),
    							myResultSet.getLong("bw_limit"),
    							myResultSet.getLong("current_user_usage"),
    							myResultSet.getLong("current_total_usage"),
    							myResultSet.getString("terminal_name"),
    							myResultSet.getLong("total_bw"),
    							myResultSet.getLong("total_data"));
    				}
    				
        	 	} catch (Exception exc) {//handle exceptions here
        	 		exc.printStackTrace();
        	 	} finally { //cleanup
        	 		if (myResultSet != null) {
        	 			//    myResultSet.close();
        	 		} 
        	 		if (myStatement != null) {
        	 			//  myStatement.close();
        	 		}
        	 	}
                 
    		try{
    			myConnection.close();
    			return(RULES);
    		}catch(SQLException e){
    			System.out.println("Could not close connetion: "+e.getMessage());
    		}
    		/***
    		 * Should something go wrong with SQL return null	
    		 */
    		return(null); 	
            }
    }
