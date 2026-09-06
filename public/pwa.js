(function () {
  if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));

  const sidebar = document.getElementById('sidebar');
  if (sidebar) {
    const backdrop = document.createElement('button');
    backdrop.type = 'button';
    backdrop.className = 'sidebar-backdrop';
    backdrop.setAttribute('aria-label', 'Закрыть меню');
    backdrop.addEventListener('click', () => sidebar.classList.remove('open'));
    document.body.appendChild(backdrop);
    sidebar.querySelectorAll('.nav-item').forEach(item => item.addEventListener('click', () => {
      if (window.matchMedia('(max-width: 900px)').matches) sidebar.classList.remove('open');
    }));
  }

  let installPrompt = null;
  const standalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  const isIos = /iphone|ipad|ipod/i.test(navigator.userAgent);
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'pwa-install-button';
  button.innerHTML = '<span aria-hidden="true"></span><b>Установить приложение</b>';
  button.hidden = true;
  const footer = document.querySelector('.sidebar-footer');
  if (footer) footer.insertBefore(button, footer.firstChild);
  else document.body.appendChild(button);

  function showIosHelp() {
    const overlay = document.createElement('div');
    overlay.className = 'pwa-install-help';
    overlay.innerHTML = '<div role="dialog" aria-modal="true" aria-labelledby="pwaInstallTitle"><button type="button" class="pwa-install-close" aria-label="Закрыть">×</button><span class="pwa-install-logo" aria-hidden="true"></span><h2 id="pwaInstallTitle">Установить приложение</h2><p>Нажмите кнопку «Поделиться» в Safari, затем выберите «На экран Домой».</p><button type="button" class="btn btn--primary pwa-install-ok">Понятно</button></div>';
    const close = () => overlay.remove();
    overlay.addEventListener('click', event => { if (event.target === overlay) close(); });
    overlay.querySelector('.pwa-install-close').addEventListener('click', close);
    overlay.querySelector('.pwa-install-ok').addEventListener('click', close);
    document.body.appendChild(overlay);
  }

  button.addEventListener('click', async () => {
    if (installPrompt) {
      installPrompt.prompt();
      await installPrompt.userChoice;
      installPrompt = null;
      button.hidden = true;
    } else if (isIos) showIosHelp();
  });

  if (!standalone && isIos) button.hidden = false;
  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    installPrompt = event;
    if (!standalone) button.hidden = false;
  });
  window.addEventListener('appinstalled', () => { installPrompt = null; button.hidden = true; });
})();
