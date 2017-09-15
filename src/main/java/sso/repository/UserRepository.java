package sso.repository;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import sso.db.DataSourceFactory;
import sso.model.User;

public class UserRepository {

	public static User findBy(String login) {
		final DataSource dataSource = DataSourceFactory.getOracleDataSource();
		final String sql = "SELECT * FROM USERS WHERE USERNAME = '" + login + "'";
		User user = null;
		try {
			final Connection connection = dataSource.getConnection();
			final Statement statement = connection.createStatement();
			final ResultSet result = statement.executeQuery(sql);
			
			while (result.next()) {
				user = new User();
//				user.setId(result.getLong("ID"));
				user.setLogin(result.getString("USERNAME"));
				user.setPassword(result.getString("PASSWORD"));
			}
			
		} catch (SQLException e) {
			e.printStackTrace();
		}

		return user;
	}
}
