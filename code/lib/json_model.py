import json
import os

class Json_Model:

    def __init__(self, file_path):
        """
        Initialize the token_model instance, loading data from a JSON file.
        
        Args:
            file_path (str): Path to the JSON file.
        """

        self.file_path = file_path
        self._data = {}

        # Load existing JSON data if the file exists; otherwise, use an empty dictionary.
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r') as file:
                    self._data = json.load(file)
            except json.JSONDecodeError:
                print("Error: The file content is not valid JSON. Starting with an empty dictionary.")
            except Exception as e:
                print(f"Error reading file: {e}")
        else:
            # Optionally, create the file if it doesn't exist, or just start with an empty dict.
            self.save()

    def is_empty(self):
        return len(self._data) == 0

    def get(self, key):
        """
        Get the value associated with a key in the JSON data.
        
        Args:
            key (str): The key to retrieve.
            
        Returns:
            The value associated with the key, or None if the key does not exist.
        """
        return self._data.get(key)

    def set(self, key, value):
        """
        Set the value for a key in the JSON data and save the file.
        
        Args:
            key (str): The key to update or add.
            value (Any): The value to associate with the key.
        """
        self._data[key] = value
        self.save()

    def save(self):
        """
        Save the internal data dictionary to the JSON file.
        """
        try:
            with open(self.file_path, 'w') as file:
                json.dump(self._data, file, indent=4)
            #print("Data saved successfully.")
        except Exception as e:
            print(f"Error writing to file: {e}")

    def put(self, key, value):
        """
            different from set as it does not save to file, just updates _data dictionary            
        """
        self._data[key] = value

    


# Example usage:
if __name__ == "__main__":
    # Specify the JSON file to work with.
    token = Json_Model("token_data.json")
    
    # Get a value (returns None if key doesn't exist)
    current_token = token.get("auth_token")
    print("Initial auth_token:", current_token)
    
    # Set a new value for the key and save the JSON file
    token.set("auth_token", "new_token_value")
    print("Updated auth_token:", token.get("auth_token"))
