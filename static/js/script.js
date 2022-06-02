const heroBtnEle = document.querySelector(".header__link-icon");
const moonEle = document.querySelector(".moon");
const sunEle = document.querySelector(".sunny");
const bodyEle = document.querySelector("body");
const imgEle = document.querySelector(".benefits__main-box--img");
const imgEle2 = document.querySelector(".sign_up_now__main-box--img");

// Toggle Light and Dark theme
heroBtnEle.addEventListener("click", function () {
  bodyEle.classList.toggle("light-theme");
  bodyEle.classList.toggle("dark-theme");
  sunEle.classList.toggle("hidden");
  moonEle.classList.toggle("hidden");

  // Invert img color
  imgEle.classList.toggle("invert_img");
  imgEle2.classList.toggle("invert_img");
});

// Showing the benefits
const benefitButton = document.querySelector(".benefits__main-box--text--2");
const benefitList = document.querySelector(".benefits__list");

benefitButton.addEventListener("click", function () {
  benefitList.classList.toggle("hidden_benefits");
  benefitList.classList.toggle("show_benefits");
});

// BENEFITS_link

const featureEle1 = document.querySelector(".benefits--text--1");
const featureEle2 = document.querySelector(".benefits--text--2");
const featureEle3 = document.querySelector(".benefits--text--3");
const featureEle4 = document.querySelector(".benefits--text--4");
const featureEle5 = document.querySelector(".benefits--text--5");
const paraEle1 = document.querySelector(".benefits__para--1");
const paraEle2 = document.querySelector(".benefits__para--2");
const paraEle3 = document.querySelector(".benefits__para--3");
const paraEle4 = document.querySelector(".benefits__para--4");
const paraEle5 = document.querySelector(".benefits__para--5");
const backgroundEle = document.querySelector(".benefits__background");

featureEle1.addEventListener("click", function () {
  backgroundEle.classList.toggle("background__scaleup");
  paraEle1.classList.toggle("hidden__para");
  bodyEle.classList.toggle("hide_overflow");
  featureEle1.classList.toggle("imp_benefit_link");
});
featureEle2.addEventListener("click", function () {
  backgroundEle.classList.toggle("background__scaleup");
  paraEle2.classList.toggle("hidden__para");
  bodyEle.classList.toggle("hide_overflow");
  featureEle2.classList.toggle("imp_benefit_link");
});
featureEle3.addEventListener("click", function () {
  backgroundEle.classList.toggle("background__scaleup");
  paraEle3.classList.toggle("hidden__para");
  bodyEle.classList.toggle("hide_overflow");
  featureEle3.classList.toggle("imp_benefit_link");
});
featureEle4.addEventListener("click", function () {
  backgroundEle.classList.toggle("background__scaleup");
  paraEle4.classList.toggle("hidden__para");
  bodyEle.classList.toggle("hide_overflow");
  featureEle4.classList.toggle("imp_benefit_link");
});
featureEle5.addEventListener("click", function () {
  backgroundEle.classList.toggle("background__scaleup");
  paraEle5.classList.toggle("hidden__para");
  bodyEle.classList.toggle("hide_overflow");
  featureEle5.classList.toggle("imp_benefit_link");
});
