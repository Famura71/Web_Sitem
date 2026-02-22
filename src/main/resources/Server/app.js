const links = document.querySelectorAll(".nav a");
const langButtons = document.querySelectorAll(".lang-btn");
const reportsButton = document.querySelector(".reports-button");
const experienceSection = document.querySelector("#tecrubelerim");
const experienceCards = document.querySelectorAll(".experience-card");
const experienceOverlay = document.querySelector(".experience-overlay");
const experienceOverlayTitle = document.querySelector(".experience-overlay-title");
const experienceOverlayBody = document.querySelector(".experience-overlay-body");
const experienceOverlayPhoto = document.querySelector(".experience-overlay .experience-photo");
const reportLinks = document.querySelectorAll("[data-pdf]");
const reportsFrame = document.querySelector(".reports-frame");
const reportsEmpty = document.querySelector(".reports-empty");
const contactForm = document.querySelector("[data-contact-form]");
const contactStatus = document.querySelector(".contact-status");
let currentLanguage = "tr";
let activeExperienceKey = null;

const translations = {
  tr: {
    "nav.about": "Hakkımda",
    "nav.projects": "Projelerim",
    "nav.experience": "Tecrübelerim",
    "nav.contact": "İletişim",
    "nav.references": "Referanslarım",
    "hero.eyebrow": "Kişisel Portfolyom",
    "hero.title": "Merhaba, ben Furkan Ahmet Karabulut.",
    "hero.lead": "Junior Fullstack Yazılım Mühendisi",
    "hero.ctaProjects": "Projelerim",
    "hero.ctaContact": "Bana Ulaş",
    "about.title": "Hakkımda",
    "about.body": "TED Üniversitesi Yazılım Mühendisliği bölümünden mezun oldum (Ocak 2026). Backend, oyun teknolojileri ve sistem geliştirme alanlarında projeler ürettim. Özellikle espor dünyasında Famura olarak biliniyorum, yazılım sektöründe de birçok yerde bu adı kullanıyorum.",
    "projects.title": "Projelerim",
    "projects.reports": "Proje Raporlarım",
    "projects.janus.title": "Janus",
    "projects.janus.body": "Wi-fi üzerinden dosyaları byte byte bölerek göndermeye yarayan proje.",
    "projects.janus.footer": "C++, Winsock",
    "projects.theia.title": "Theia",
    "projects.theia.body": "Windows üzerinde monitör oluşturup bunu bir Android cihaza Wi-fi üzerinden paylaşmak için geliştirdim.",
    "projects.theia.footer": "C++, Winsock, Android Studio",
    "projects.web.title": "Web Sitem",
    "projects.web.body": "Şu an size kendimi anlatmamı sağlayan web sitesi.",
    "projects.web.footer": "HTML, CSS, JS",
    "projects.trieme.title": "Trieme",
    "projects.trieme.body": "2024 Teknofest yarışmasına katıldığım İnsansız Deniz Aracı projem.",
    "projects.trieme.footer": "Python, MAVLink",
    "projects.goksu.title": "Göksu",
    "projects.goksu.body": "2025 Teknofest yarışmasına katıldığım İnsansız Deniz Aracı projem.",
    "projects.goksu.footer": "Python, MAVLink, AI",
    "projects.interbank.title": "Interbank Payment Service",
    "projects.interbank.body": "Okulda dönem projem için geliştirdiğim bankalar arası ödeme ve hesap sistemi.",
    "projects.interbank.footer": "Java, Hibernate, MySQL, Kafka, SOAP API, HTML, CSS",
    "projects.aelita.title": "Aelita",
    "projects.aelita.body": "Göksu projesinde geliştirilen AI modelini kişisel kullanım için geliştiriyorum.",
    "projects.aelita.footer": "AI, Makine Öğrenmesi, Windows Araçları",
    "projects.moba.title": "MOBA Manager",
    "projects.moba.body": "Football Manager serisinden esinlenerek bir MOBA Manager oyunu geliştiriyorum. Hala geliştirme aşamasında.",
    "projects.moba.footer": "Java, JavaFX, OpenCL, SQLite",
    "experience.title": "Tecrubelerim",
    "experience.one.title": "Türk Telekom",
    "experience.one.body": "Stajyer - Analiz ve Çevik Çözümler",
    "experience.one.date": "2025 Temmuz - 2026 Ocak",
    "experience.one.detail": "Türk Telekom’un “Start Stajım” programının bir parçası oldum. Proje analiz ve çevik çözümler ekibinde çalıştım. Kısa dönem stajımı yaptıktan sonra uzun dönem stajına kabul aldım ve devamlılığı benim isteğime bağlı olarak 2026 Ocak ayına kadar stajyer olarak çalışma hakkı elde ettim.",
    "experience.two.title": "YD Yazılım",
    "experience.two.body": "Stajyer - Fullstack Developer",
    "experience.two.date": "2023 Temmuz - 2023 Eylül",
    "experience.two.detail": "YD Yazılım bünyesinde staj yaptım. Bir toplantı uygulaması ve bir üniversite için öğrenme yönetim sistemi üzerine çalıştım. Deneyimli yazılım mühendisleriyle birlikte çalıştım.",
    "experience.three.title": "Esportimes",
    "experience.three.body": "Yazar/Çevirmen - Yarı Zamanlı Çalışan",
    "experience.three.date": "2022 Kasım - 2024 Şubat",
    "experience.three.detail": "Esportimes’ın yazar kadrosunda bulundum ve hem yazarlık hem çevirmenlik yaptım. Genellikle espor içerikleri ürettim ve yabancı kaynakları Türkçe'ye, iş arkadaşlarımın ürettikleri içerikleri İngilizce'ye çevirdim. Tamamen uzaktan çalıştım.",
    "experience.detailTitle": "Detaylar",
    "references.title": "Referanslar",
    "references.one.name": "Neslihan Akkoç",
    "references.one.role": "Kıdemli İş Analisti - Türk Telekom",
    "references.one.note": "Türk Telekom'da birlikte çalıştığım, kıdemli iş analisti. Türk Telekom'daki staj sürecim boyunca benden kendisi sorumluydu. Kendisi 12 seneyi aşkın bir süredir Türk Telekom çatısı altında çalışmaktadır.",
    "references.two.name": "Çağrı Yüzbaşıoğlu",
    "references.two.role": "Kurucu - ISSD",
    "references.two.note": "Kendisi ile iş arama sürecimde tanıştım. ISSD adlı şirketin kurucusu ve yöneticisi. ellikle akıllı ulaşım sistemleri, trafik yönetimi, elektronik denetleme ve danışmanlık hizmetleriyle 2009’dan beri sektöründe faaliyet göstermektedir ve teknolojilerini 20’den fazla ülkede uygulamaktadır.",
    "contact.title": "İletisim",
    "contact.nameLabel": "İsim",
    "contact.namePlaceholder": "İsim",
    "contact.messageLabel": "Mesaj",
    "contact.messagePlaceholder": "Mesaj",
    "contact.fileLabel": "Dosya Sec",
    "contact.send": "Gönder",
    "footer.copyright": "© 2026 Furkan Ahmet Karabulut. Bütün hakları saklıdır"
  },
  en: {
    "nav.about": "About",
    "nav.projects": "Projects",
    "nav.experience": "Experience",
    "nav.contact": "Contact",
    "nav.references": "References",
    "hero.eyebrow": "Personal Portfolio",
    "hero.title": "Hi, I'm Furkan Ahmet Karabulut.",
    "hero.lead": "Junior Fullstack Software Engineer",
    "hero.ctaProjects": "View Projects",
    "hero.ctaContact": "Contact Me",
    "about.title": "About",
    "about.body": "I graduated from TED University’s Software Engineering department (January 2026). I have built projects in backend, game technologies, and systems development. I am especially known as Famura in the esports world, and I also use this name in many places in the software industry.",
    "projects.title": "Projects",
    "projects.reports": "Reports",
    "projects.janus.title": "Janus",
    "projects.janus.body": "A project that sends files over Wi-Fi by splitting them byte by byte.",
    "projects.janus.footer": "C++, Winsock",
    "projects.theia.title": "Theia",
    "projects.theia.body": "I built this to create a virtual monitor on Windows and stream it to an Android device over Wi-Fi.",
    "projects.theia.footer": "C++, Winsock, Android Studio",
    "projects.web.title": "My Website",
    "projects.web.body": "The website you are reading to learn about me.",
    "projects.web.footer": "HTML, CSS, JS",
    "projects.trieme.title": "Trieme",
    "projects.trieme.body": "My unmanned marine vehicle project for the 2024 Teknofest competition.",
    "projects.trieme.footer": "Python, MAVLink",
    "projects.goksu.title": "Göksu",
    "projects.goksu.body": "My unmanned marine vehicle project for the 2025 Teknofest competition.",
    "projects.goksu.footer": "Python, MAVLink, AI",
    "projects.interbank.title": "Interbank Payment Service",
    "projects.interbank.body": "An interbank payment and account system I built for a term project at school.",
    "projects.interbank.footer": "Java, Hibernate, MySQL, Kafka, SOAP API, HTML, CSS",
    "projects.aelita.title": "Aelita",
    "projects.aelita.body": "I am developing the AI model built in the Goksu project for personal use.",
    "projects.aelita.footer": "AI, Machine Learning, Windows Tools",
    "projects.moba.title": "MOBA Manager",
    "projects.moba.body": "A MOBA Manager game inspired by the Football Manager series. It is in the development stage.",
    "projects.moba.footer": "Java, JavaFX, OpenCL, SQLite",
    "experience.title": "Experience",
    "experience.one.title": "Turk Telekom",
    "experience.one.body": "Intern - Project Analyst",
    "experience.one.date": "July 2025 - January 2026",
    "experience.one.detail": "I joined Turk Telekom’s “Start Stajim” program and worked in the Project Analysis and Agile Solutions team. After completing the short-term internship, I was accepted for a long-term internship and continued as an intern until January 2026 by my own choice.",
    "experience.two.title": "YD Yazilim",
    "experience.two.body": "Intern - Fullstack Developer",
    "experience.two.date": "July 2023 - September 2023",
    "experience.two.detail": "I interned at YD Yazilim, working on a meeting application and a learning management system for a university. I collaborated with experienced software engineers.",
    "experience.three.title": "Esportimes",
    "experience.three.body": "Writer/Translator - Part-time",
    "experience.three.date": "November 2022 - February 2024",
    "experience.three.detail": "I was part of Esportimes’ writing team and worked as both a writer and translator. I mainly produced esports content and translated foreign sources into Turkish, while translating my teammates’ content into English. I worked fully remotely.",
    "experience.detailTitle": "Details",
    "references.title": "References",
    "references.one.name": "Neslihan Akkoc",
    "references.one.role": "Senior Business Analyst - Turk Telekom",
    "references.one.note": "A senior business analyst I worked with at Turk Telekom. She was responsible for me throughout my internship at Turk Telekom. She has over 12 years of experience working at Türk Telekom.",
    "references.two.name": "Cagri Yuzbasioglu",
    "references.two.role": "Founder - ISSD",
    "references.two.note": "I met him during my job search. He is the founder and executive of ISSD, which has operated in its field since 2009, mainly in intelligent transportation systems, traffic management, electronic enforcement, and consulting services, and has deployed its technologies in more than 20 countries.",
    "contact.title": "Contact",
    "contact.nameLabel": "Name",
    "contact.namePlaceholder": "Name",
    "contact.messageLabel": "Message",
    "contact.messagePlaceholder": "Message",
    "contact.fileLabel": "Choose File",
    "contact.send": "Send",
    "footer.copyright": "© 2026 Furkan Ahmet Karabulut. All rights reserved."
  }
};

const applyLanguage = (lang) => {
  currentLanguage = lang;
  document.documentElement.setAttribute("lang", lang);
  const dictionary = translations[lang] || translations.tr;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    const key = element.getAttribute("data-i18n");
    if (dictionary[key]) {
      element.textContent = dictionary[key];
    }
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    const key = element.getAttribute("data-i18n-placeholder");
    if (dictionary[key]) {
      element.setAttribute("placeholder", dictionary[key]);
    }
  });
  langButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.lang === lang);
  });
  try {
    localStorage.setItem("lang", lang);
  } catch (error) {
    // Ignore storage errors in restricted contexts.
  }
  if (activeExperienceKey) {
    updateExperienceOverlay(activeExperienceKey);
  }
};

if (reportsButton) {
  reportsButton.addEventListener("click", () => {
    const target = currentLanguage === "en" ? "/Reports.html?lang=en" : "/Raporlar.html?lang=tr";
    window.location.href = target;
  });
}

const updateExperienceOverlay = (card) => {
  const dictionary = translations[currentLanguage] || translations.tr;
  const titleKey = card.dataset.titleKey;
  const detailKey = card.dataset.detailKey;
  const detailImg = card.dataset.detailImg;
  if (experienceOverlayTitle && titleKey && dictionary[titleKey]) {
    experienceOverlayTitle.textContent = dictionary[titleKey];
  }
  if (experienceOverlayBody && detailKey && dictionary[detailKey]) {
    experienceOverlayBody.textContent = dictionary[detailKey];
  }
  if (experienceOverlayPhoto && detailImg) {
    experienceOverlayPhoto.setAttribute("src", detailImg);
  }
  activeExperienceKey = card;
  if (experienceSection) {
    experienceSection.classList.add("experience-overlay-active");
  }
};

if (experienceSection && experienceOverlay) {
  experienceCards.forEach((card) => {
    card.addEventListener("mouseenter", () => {
      updateExperienceOverlay(card);
    });
  });
  experienceSection.addEventListener("mouseleave", () => {
    experienceSection.classList.remove("experience-overlay-active");
    activeExperienceKey = null;
  });
}

if (reportLinks.length && reportsFrame) {
  reportLinks.forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      const pdf = link.dataset.pdf;
      if (!pdf) {
        return;
      }
      reportsFrame.setAttribute("src", pdf);
      if (reportsEmpty) {
        reportsEmpty.style.display = "none";
      }
      reportLinks.forEach((item) => item.classList.remove("is-active"));
      link.classList.add("is-active");
    });
  });
  const first = reportLinks[0];
  if (first && first.dataset.pdf) {
    reportsFrame.setAttribute("src", first.dataset.pdf);
    if (reportsEmpty) {
      reportsEmpty.style.display = "none";
    }
    first.classList.add("is-active");
  }
}

langButtons.forEach((button) => {
  button.addEventListener("click", () => {
    applyLanguage(button.dataset.lang);
  });
});

links.forEach((link) => {
  link.addEventListener("click", (event) => {
    const target = document.querySelector(link.getAttribute("href"));
    if (!target) {
      return;
    }
    event.preventDefault();
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

const params = new URLSearchParams(window.location.search);
const storedLang = (() => {
  try {
    return localStorage.getItem("lang");
  } catch (error) {
    return null;
  }
})();
const initialLang = params.get("lang") || storedLang || "tr";
applyLanguage(initialLang);

window.addEventListener("load", () => {
  window.scrollTo({ top: 0, left: 0, behavior: "auto" });
});

if (contactForm) {
  contactForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submitButton = contactForm.querySelector("button[type=\"submit\"]");
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = currentLanguage === "en" ? "Sending..." : "Gonderiliyor...";
    }
    if (contactStatus) {
      contactStatus.textContent = "";
    }
    try {
      const formData = new FormData(contactForm);
      const response = await fetch(contactForm.getAttribute("action") || "/api/contact", {
        method: "POST",
        body: formData
      });
      if (response.ok) {
        if (contactStatus) {
          contactStatus.textContent = currentLanguage === "en" ? "Sent" : "Gönderildi";
        }
        contactForm.reset();
      } else {
        if (contactStatus) {
          contactStatus.textContent = currentLanguage === "en" ? "An error occurred" : "Bir hata ile karşılaşıldı";
        }
      }
    } catch (error) {
      if (contactStatus) {
        contactStatus.textContent = currentLanguage === "en" ? "An error occurred" : "Bir hata ile karşılaşıldı";
      }
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = currentLanguage === "en" ? "Send" : "Gonder";
      }
    }
  });
}
