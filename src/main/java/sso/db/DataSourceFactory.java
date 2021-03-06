package sso.db;

import java.sql.SQLException;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import oracle.jdbc.pool.OracleDataSource;

@Configuration
public class DataSourceFactory {

	@Bean
	public static DataSource getOracleDataSource() {
		OracleDataSource oracleDS = null;
		try {
			oracleDS = new OracleDataSource();
			oracleDS.setURL("jdbc:oracle:thin:@10.42.12.36:1521:oracode");
			oracleDS.setUser("CODE_SUENAGA");
			oracleDS.setPassword("CODE_SUENAGA");
		} catch (SQLException e) {
			e.printStackTrace();
		}

		return oracleDS;
	}
	
}
