import { useEffect, useState } from "react";
import axios from "axios";

export default function GeoLocation() {
  const [location, setLocation] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios
      .get(`http://ip-api.com/json/${location}`)
      .then((res) => setLocation(res.data))
      .catch(() => setError("Failed to fetch location"));
  }, [location]);

  return (
    <div>
      <div class="mb-6">
        <label
          for="large-input"
          class="block mb-2 text-sm font-medium text-gray-900 dark:text-white"
        >
          IP Address
        </label>
        <input
          type="text"
          id="large-input"
          
          class="block w-full p-4 text-gray-900 border border-gray-300 rounded-lg bg-gray-50 text-base focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
        />
      </div>
      <button
            onClick={(e) => setLocation(e.target.value)}
            type="button"
            className="text-white ml-5 bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:ring-blue-300 font-medium rounded-full text-sm px-5 py-2.5 me-2 mb-2 dark:bg-blue-600 dark:hover:bg-blue-700 focus:outline-none dark:focus:ring-blue-800"
          >
            Upload
          </button>
      <h2>Geolocation Data</h2>
      {error ? (
        <p>{error}</p>
      ) : location ? (
        <div>
          <p>
            <strong>IP:</strong> {location.query}
          </p>
          <p>
            <strong>City:</strong> {location.city}
          </p>
          <p>
            <strong>Country:</strong> {location.country}
          </p>
          <p>
            <strong>Latitude:</strong> {location.lat}
          </p>
          <p>
            <strong>Longitude:</strong> {location.lon}
          </p>
          <p>
            <strong>ISP:</strong> {location.isp}
          </p>
        </div>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
}
