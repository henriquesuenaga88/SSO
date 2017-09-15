package sso.configs;

import javax.sql.DataSource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;

import sso.db.DataSourceFactory;

@SpringBootApplication
@EnableAutoConfiguration(exclude={
	    DataSourceAutoConfiguration.class,
	    DataSourceTransactionManagerAutoConfiguration.class
	})
public class Application {
    
    @Bean(name = "dataSource")
    public DataSource dataSource() {
    	return DataSourceFactory.getOracleDataSource();
    }

    public static void main(String[] args) throws Throwable {
        ConfigurableApplicationContext context = SpringApplication.run(Application.class, args);
    }
}