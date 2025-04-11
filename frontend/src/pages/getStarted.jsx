import React, { useState } from "react";
import axios from "axios";

export default function GetStarted() {
  const [files, setFiles] = useState(null);
  const uploadFile = (e) => {
    setFiles(e.target.files[0]);
  };

  const handleUpload = async () => {
        if (!files) {
            alert("Please select a file to upload");
            return;
        }

        const formData = new FormData();
        formData.append("file", files);
        try {
            const response = await axios.post("http://localhost:5000/upload", formData, { 
              headers: {
                "Content-Type": "multipart/form-data",
              },
            });
      
            console.log("Upload successful:", response.data);
            alert("File uploaded successfully!");
          } catch (error) {
            console.error("Upload error:", error);
            alert("File upload failed.");
          }
  };
  return (
    <div className="flex items-center justify-center flex-col w-full h-screen bg-blue-50 p-4">
      <div className="upper-section">
        <h1 className="title mb-3">UPLOAD YOUR FILE HERE(.pcap)</h1>
        <div className="mt-4">
          <label
            class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
            for="file_input"
          >
            Upload file
          </label>
          <input
            class="block w-full text-sm text-gray-900 border border-gray-300 rounded-lg cursor-pointer bg-gray-50 dark:text-gray-400 focus:outline-none dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400"
            aria-describedby="file_input_help"
            id="file_input"
            type="file"
            onChange={uploadFile}
          />
          <p
            class="mt-1 text-sm text-gray-500 dark:text-gray-300"
            id="file_input_help"
          >
            PCAP.
          </p>
        </div>
        <div className="flex items-center justify-center ">
          <button
            onClick={handleUpload}
            type="button"
            className="text-white ml-5 bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:ring-blue-300 font-medium rounded-full text-sm px-5 py-2.5 me-2 mb-2 dark:bg-blue-600 dark:hover:bg-blue-700 focus:outline-none dark:focus:ring-blue-800"
          >
            Upload
          </button>
        </div>
      </div>

      <div className="lower-section">view your files</div>
    </div>
  );
}
