package JDBC;

import java.sql.Time;
import java.math.BigInteger;
public class multi_Type {
	private boolean a1;	//block
	private long a2;	//usr limit
	private long a3;	//total limit
	private java.sql.Time a4;	//start time
	private java.sql.Time a5;	//stope time
	private long a6; 	//bandwidth
	private long a7; 	//current user usage
	private long a8;	//current total usage
	private String a9;	//terminal name
	private long a10;	//total bandwidth
	private long a11;	//total data
	
	public multi_Type(boolean boolean1, long int1, long int2, Time time,
			Time time2, long BW, long UsrUsage, long totUsage, String name, long totalBW, long totalData) {
	    a1 = boolean1;
	    a2 = int1;
	    a3 = int2;
	    a4 = time;
		a5 = time2;
		a6 = BW;
		a7 = UsrUsage;
		a8 = totUsage;
		a9 = name;
		a10 = totalBW;
		a11 = totalData;
		
	}
	public boolean getBlock(){
		return(this.a1);
	}
	public long getUsrUsageLimit(){
		return(this.a2);
	}
	public long getTotalUsageLimit(){
		return(this.a3);
	}
	public java.sql.Time getStartTime(){
		return(this.a4);
	}
	public java.sql.Time getStopTime(){
		return(this.a5);
	}
	public long getBandwidth(){
		return(this.a6);
	}
	public long getUsrUsage(){
		return(this.a7);
	}
	public long getNetworkUsage(){
		return(this.a8);
	}
	public String getName(){
		return(this.a9);
	}
	public long getTotalBandwidth(){
		return(this.a10);
	}
	public long getTotalDataLimit(){
		return(this.a11);
	}
	
	
}
