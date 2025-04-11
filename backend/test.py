from pymongo import MongoClient
import pyshark

connection_string = "mongodb+srv://dummy:dummy@cluster0.a6vbf.mongodb.net/testdb?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(connection_string)
db = client["testdb"]  
collection = db["items"] 

# try:
#     packets = pyshark.FileCapture('Forensic_challenge_4.pcap', display_filter='sip')
#     print("PCAP file loaded successfully.")
# except Exception as e:
#     print(f"Error loading pcap file: {e}")
#     packets = None



def save_pcap_to_mongodb(file_path, collection):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
        print(file_data)
        document = {
            "filename": "Forensic_challenge_4.pcap",
            "file_data": file_data
        }
        result = collection.insert_one(document)
        print(f"File saved to MongoDB with ID: {result.inserted_id}")
    except Exception as e:
        print(f"Error saving file to MongoDB: {e}")

# Retrieve the .pcap file from MongoDB
def retrieve_pcap_from_mongodb(filename, collection):
    try:
        document = collection.find_one({"filename": filename})
        if document:
            with open(f"retrieved_{filename}", "wb") as f:
                f.write(document["file_data"])
            print(f"File retrieved and saved as 'retrieved_{filename}'")
        else:
            print("File not found in MongoDB.")
    except Exception as e:
        print(f"Error retrieving file from MongoDB: {e}")

# Test the connection
try:
    print("Connected to MongoDB!")
    # Save and retrieve the file
    save_pcap_to_mongodb("Forensic_challenge_4.pcap", collection)
  
except Exception as e:
    print("Error:", e)