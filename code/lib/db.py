import sqlite3
from lib.common import log, error


class SQLiteDB:
    _instance = None

    def __new__(cls, db_file, table_name):
        if not cls._instance:
            cls._instance = super(SQLiteDB, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_file, table_name):
        if self._initialized:
            return
        self.db_file = db_file
        self.__table_name = table_name  # Private table name
        self.connection = None
        self.cursor = None
        self._initialized = True

    def __del__(self):
        """
        Destructor that attempts to close the database connection.
        Note: The timing of __del__ is non-deterministic.
        """
        try:
            self.close()
        except sqlite3.ProgrammingError as e:
            log("threads issue while closing connection") 

    def connect(self):
        """
        Establish a connection to the SQLite database.
        """
        try:
            self.connection = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.connection.cursor()
            #log(f"Connected to database: {self.db_file}")
        except sqlite3.Error as e:
            error("Connection error:", e)

    def ensure_connection(self):
        """
        Ensure that the database connection is open.
        """
        if self.connection is None:
            self.connect()

    def close(self):
        """
        Close the SQLite database connection.
        """
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None
            #log("Database connection closed.")
    
    @property
    def table_name(self):  # Getter
        return self.__table_name
    
    @table_name.setter
    def table_name(self, table):  # Setter
        self.__table_name = table
    


    def execute_query(self, query, params=None):
        """
        Execute a query that modifies the database (e.g., INSERT, UPDATE, DELETE).
        """
        #log(query)
        self.ensure_connection()
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            self.connection.commit()
            #log("Query executed successfully.")
        except sqlite3.Error as e:
            error("Error executing query:", e)

    def fetch_all(self, query, params=None):
        """
        Execute a SELECT query and return all rows.
        """
        #log(query)
        self.ensure_connection()
        try:
            if params:                
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            rows = self.cursor.fetchall()
            return rows
        except sqlite3.Error as e:
            error("Error fetching data:", e)
            return None

    def create_table(self, create_table_sql):
        """
        Create a table using the provided SQL statement.
        """
        self.execute_query(create_table_sql)

    def insert_record(self, *args):
        """
        Insert a record into the table.
        The following parameters should be provided in pairs: the first in each pair is the field name
        and the second is the value.
        
        Example:
            db.insert_record('name', 'Alice', 'email', 'alice@example.com')
        
        Raises:
            ValueError: If an odd number of parameters is provided.
        """
        if len(args) % 2 != 0:
            raise ValueError("Fields and values must be provided in pairs.")
        
        self.ensure_connection()
        fields = []
        values = []
        for i in range(0, len(args), 2):
            fields.append(args[i])
            values.append(args[i + 1])
        
        placeholders = ', '.join(['?'] * len(values))
        field_list = ', '.join(fields)
        query = f"INSERT INTO {self.__table_name} ({field_list}) VALUES ({placeholders})"
        self.execute_query(query, tuple(values))



    def update_record(self, where_clause, *args):
        """
        Update records in the table.
        The first parameter is the WHERE clause, and the following parameters should be provided in pairs:
        field name and new value.
        
        Example:
            db.update_record("id = 1", "name", "Alice Updated", "email", "alice_new@example.com")
        
        Raises:
            ValueError: If an odd number of parameters is provided.
        """
        if len(args) % 2 != 0:
            raise ValueError("Fields and values must be provided in pairs.")

        self.ensure_connection()
        assignments = []
        values = []
        for i in range(0, len(args), 2):
            assignments.append(f"{args[i]} = ?")
            values.append(args[i + 1])
        
        query = f"UPDATE {self.__table_name} SET {', '.join(assignments)} WHERE {where_clause}"  
        self.execute_query(query, tuple(values))


    def select_with_where(self, where_clause, params=None):
        """
        Run a SELECT query on the table using the provided WHERE clause.
        
        Args:
            where_clause (str): The WHERE clause to filter results.
            params (tuple, optional): Parameters to safely inject into the query.
        
        Returns:
            list: List of rows resulting from the query.
        """
        self.ensure_connection()
        query = f"SELECT * FROM {self.__table_name} WHERE {where_clause}"
        return self.fetch_all(query, params)

    def select_by_fields(self, *args):
        """
        Run a SELECT query on the table by constructing a WHERE clause from field-value pairs.
        The parameters should be provided in pairs: the first in each pair is the field name and the second is the value.
        
        Example:
            db.select_by_fields('name', 'Alice', 'email', 'alice@example.com')
        
        Returns:
            list: List of rows resulting from the query.
        
        Raises:
            ValueError: If an odd number of parameters is provided.
        """
        if len(args) % 2 != 0:
            raise ValueError("Fields and values must be provided in pairs.")
        
        self.ensure_connection()
        conditions = []
        values = []
        for i in range(0, len(args), 2):
            conditions.append(f"{args[i]} = ?")
            values.append(args[i + 1])
        
        where_clause = " AND ".join(conditions)
        return self.select_with_where(where_clause, tuple(values))

    def does_record_exist(self, where_clause, params=None):
        """
        Check if a record exists in the table based on the provided WHERE clause.
        It calls the select function, counts the results, and returns True if at least one record exists.
        
        Args:
            where_clause (str): The WHERE clause for filtering the records.
            params (tuple, optional): Parameters to safely inject into the query.
        
        Returns:
            bool: True if at least one record exists; False otherwise.
        """
        records = self.select_with_where(where_clause, params)
        return bool(records and len(records) > 0)
    
    def initialize_database(self):
        create_identities_sql = """
            CREATE TABLE IF NOT EXISTS identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identity TEXT NOT NULL,
                generator TEXT NOT NULL,
                master_public_key TEXT NOT NULL,
                master_secret_key TEXT NOT NULL,
                partial_private_key TEXT NOT NULL,
                public_key TEXT
            );
        """    

        create_authorization_sql = """
            CREATE TABLE IF NOT EXISTS authorization (    
                id INTEGER PRIMARY KEY AUTOINCREMENT,        
                identity TEXT NOT NULL,
                can_access TEXT NOT NULL,
                current_token TEXT
            );
        """

        self.create_table(create_identities_sql)
        self.create_table(create_authorization_sql)



db = SQLiteDB("kgs.sqlite3", "identities")

if __name__ == "__main__":
    import sys
    import os
    #if len(sys.argv) > 1 and sys.argv[1] == "init" and not os.path.isfile("pkg.sqlite3"):
    db.initialize_database()


'''
# Example usage:
if __name__ == "__main__":
    # Create a singleton instance with the database file and the table name.
    db = SQLiteDB("example.db", "users")
    
    # Create the table (using the private table name set in the instance).
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    );
    """
    db.create_table(create_table_sql)
    
    # Insert records without specifying the table name.
    db.insert_record("name", "Alice", "email", "alice@example.com")
    db.insert_record("name", "Bob", "email", "bob@example.com")
    
    # Select records using a custom WHERE clause.
    logging.info("Select with custom WHERE clause:")
    result = db.select_with_where("name = ?", ("Alice",))
    logging.info(result)
    
    # Select records by specifying field-value pairs.
    logging.info("Select by fields:")
    result = db.select_by_fields("name", "Bob", "email", "bob@example.com")
    logging.info(result)
    
    # Check if a record exists using a custom WHERE clause.
    exists = db.does_record_exist("email = ?", ("alice@example.com",))
    logging.info("Does record exist (alice@example.com)?", exists)
    
    # Explicitly close the connection (destructor will also attempt this on garbage collection)
    db.close()

'''

