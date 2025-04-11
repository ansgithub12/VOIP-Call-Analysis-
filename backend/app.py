from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS
import os
import subprocess
import pyshark
import tempfile
import asyncio


temp_dir = tempfile.gettempdir()

app = Flask(__name__)
CORS(app)

client = MongoClient(
    "mongodb+srv://dummy:dummy@cluster0.a6vbf.mongodb.net/voip?retryWrites=true&w=majority&appName=Cluster0"
)
db = client.voip
collection_name = "sem"


def run_pkrscan(file_data):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
   
    try:
        packets = pyshark.FileCapture(file_data, display_filter="sip", use_json=True)
        print("going here")
    except Exception as e:
        print(f"Error loading pcap file: {e}")
        return None  

    def packet_number(file_contents):
        print("going here 2")
        count = sum(1 for _ in file_contents)
        return count

    def unique_call_id(file_contents):
        calls = {}
        for packet in file_contents:
            if hasattr(packet, "sip"):
                callid = packet.sip.get_field_value("Call-ID")
                if not callid:
                    continue

                sender = packet.sip.get_field_value("From")
                receiver = packet.sip.get_field_value("To")
                contact = packet.sip.get_field_value("Contact")  # actual device ip
                method = packet.sip.get_field_value("Method")
                status_code = packet.sip.get_field_value(
                    "Status-Code"
                )  # checking 200 OK methods - call acceptance time
                timestamp = packet.sniff_time
                # below stuff used to check for IP spoofing
                via = packet.sip.get_field_value("Via")
                sender_ip = packet.ip.src if hasattr(packet, "ip") else "Unknown"

                if callid not in calls:
                    calls[callid] = {
                        "Call ID": callid,
                        "Sender": sender,
                        "Receiver": receiver,
                        "Device IP": contact,
                        "Methods": [],
                        "Sender Actual IP": sender_ip,
                        "Via": via,
                        "Start Time": None,
                        "200 OK Time": None,  # this is call acceptance time
                        "End Time": None,
                        "Duration": None,
                    }

                if method:
                    calls[callid]["Methods"].append(method)

                if method == "INVITE":
                    calls[callid]["Start Time"] = timestamp
                if status_code == "200":
                    calls[callid]["200 OK Time"] = timestamp
                if method == "BYE":
                    calls[callid]["End Time"] = timestamp

        for callid, data in calls.items():
            start = data["Start Time"]
            end = data["End Time"]
            if start and end:
                data["Duration"] = (end - start).total_seconds()

        return calls

    # analysis_for_each_packet = unique_call_id(packets) if packets else {}
    temp = unique_call_id(packets)
    print(f"Number of packets: {temp}")
    packets.close()
    return temp


@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"message": "No file part"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "No selected file"}), 400

        if file:
            filename = file.filename
            temp_path = os.path.join(temp_dir, filename)
            file.save(temp_path)

        
            pkrscan_output = run_pkrscan(temp_path)

        

            if pkrscan_output is None:
                return jsonify({"message": "Error processing pcap file"}), 500

            document = {
                "filename": filename,
                "pkrscan_output": pkrscan_output,
            }
            collection = db[collection_name]
            result = collection.insert_one(document)
            print(f"File saved to MongoDB with ID: {result.inserted_id}")
            print(pkrscan_output)

            return (
                jsonify(
                    {
                        "message": "File uploaded successfully",
                        "filename": filename,
                        "data": pkrscan_output,
                    }
                ),
                200,
            )
        else:
            return jsonify({"message": "Allowed file types are pcap"}), 400

    except Exception as e:
        print(f"Error uploading file: {e}")
        return jsonify({"message": f"Error uploading file: {str(e)}"}), 500


@app.route("/api/data", methods=["GET"])
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


if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
