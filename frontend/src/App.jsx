import React from "react";
import {BrowserRouter as Router, Route, Routes} from "react-router-dom";
import LandingPage from "./pages/landingPage.jsx";
import GetStarted from "./pages/getStarted.jsx";
import GeoLocation from "./pages/geoLocation.jsx";

function App() {
  return (
    <div>
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/getStarted" element={<GetStarted />} />
        <Route path="/geoLocation" element={<GeoLocation />} />
      </Routes>
    </Router>
    </div>
    
  );
}

export default App;