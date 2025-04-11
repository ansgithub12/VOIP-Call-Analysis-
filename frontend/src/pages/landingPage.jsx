import React from "react";
import { useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap/dist/js/bootstrap.bundle.min";
import "../styles/landingPage.css";
import { useEffect } from "react";

export default function LandingPage() {
  const navigate = useNavigate();

  const changePage = () => {
    navigate("/getStarted");
  };
  
  const goToGeoLocation = () => {
    navigate("/geolocation"); 
  };

  useEffect(() => {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("show");
        } else {
          entry.target.classList.remove("show");
        }
      });
    });

    const hideElements = document.querySelectorAll(".hide");
    hideElements.forEach((el) => observer.observe(el));
  }, []);

  return (
    <>
      <div className="container">
        <header className="d-flex flex-wrap justify-content-center py-3">
          <p className="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-decoration-none">
            <img
              src="../images/logo.png"
              alt="CallTrace logo"
              className="logo-img"
            />
            <span className="fs-2" id="logo-name1">
              CallTrace
            </span>
          </p>
          <ul className="nav nav-pills">
            <li className="nav-item">
              <a href="#about-us" className="nav-link text-secondary">
                About Us
              </a>
            </li>
            <li className="nav-item">
              <a href="#features" className="nav-link text-secondary">
                Features
              </a>
            </li>
          </ul>
        </header>
      </div>

      <div className="hero">
        <div className="px-4 py-5 text-center">
          {/* <p id="space1"></p> */}
          <h1 className="display-5 mt-5 mb-3 fw-bold text-body-white">
            Bringing Clarity to Every Conversation.
          </h1>
          <div className="col-lg-6 mx-auto">
            <p className="lead mb-4">
              Gain clear insights into VoIP calls—analyze, secure, and optimize
              with ease. Detect threats, monitor traffic, and ensure smooth
              communication. Start today and take control of your conversations.
            </p>
            <button className="button-40" role="button">
              <span className="text" onClick={changePage}>Get Started</span>
            </button>
          </div>
        </div>
      </div>

      <div
        className="container col-xxl-8 px-4 py-5 hide about-us-cont"
        id="about-us"
      >
        <div className="row flex-lg-row-reverse align-items-center g-10 py-5">
          <div className="col-10 col-sm-8 col-lg-6">
            <img
              src="../images/Spam call.jpg"
              className="d-block mx-lg-auto img-fluid image"
              alt="Spam Call"
              width="1000"
              height="1000"
            />
          </div>
          <div className="col-lg-6">
            <h1 className="display-5 fw-bold text-body-emphasis lh-1 mb-3">
              About Us
            </h1>
            <p className="lead">
              At CallTrace, we believe in the power of clear and secure
              communication. Our advanced VoIP analysis platform helps users
              monitor, detect and optimize calls with precision, ensuring
              seamless and secure voice communication.
              <br />
              <br />
              What sets CallTrace apart is our commitment to accuracy and
              security. Using cutting-edge packet analysis and real-time
              monitoring, we identify call patterns, detect threats and provide
              valuable insights—all in a user-friendly and efficient system.
              <br />
              <br />
              Whether you're securing a network, analyzing call data or
              preventing fraud, CallTrace delivers a seamless and reliable
              experience. Stay ahead of VoIP challenges—one call at a time.
              <br />
              <br />
            </p>
          </div>
          <hr />
        </div>
      </div>

      <div className="container px-4 py-5" id="features">
        <h1 className="display-5 fw-bold text-body-emphasis pb-2 border-bottom">
          Features
        </h1>
        <div className="row g-4 py-5 row-cols-1 row-cols-lg-3">
          {[
            {
              icon: "bi-search",
              title: "Deep Packet Inspection",
              text: "Analyze SIP packets to extract key details, detect anomalies and identify security threats.",
            },
            {
              icon: "bi-telephone",
              title: "Caller Identity Analysis",
              text: "Examine caller details, IP addresses and call frequency to detect spam and VoIP fraud.",
            },
            {
              icon: "bi-globe-americas",
              title: "Geographic Call Mapping",
              text: "Track the origin of SIP calls using IP geolocation to detect fraud-prone regions.",
            },
          ].map((feature, index) => (
            <div className="feature col hide" key={index}>
              <div className="feature-icon d-inline-flex align-items-center justify-content-center bg-gradient fs-2 mb-3">
                <i
                  className={`bi ${feature.icon}`}
                  style={{ color: "white" }}
                  onClick={goToGeoLocation}
                ></i>
              </div>
              <h3 className="fs-2 text-body-emphasis">{feature.title}</h3>
              <p>{feature.text}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="container">
        <footer className="d-flex flex-wrap justify-content-between align-items-center py-3 my-4 border-top">
          <div className="col-md-4 d-flex align-items-center">
            <p className="mb-3 me-2 mb-md-0 text-body-secondary fw-bold text-decoration-none lh-1">
              <img
                src="../images/logo.png"
                alt="CallTrace logo"
                className="logo-img"
              />
              CallTrace
            </p>
            <span className="mb-3 mb-md-0 text-body-secondary">© 2025</span>
          </div>
        </footer>
      </div>
    </>
  );
}
