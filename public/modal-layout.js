(function () {
  function frameModal(modal) {
    if (modal.classList.contains('is-scroll-framed')) return;

    const existingBody = Array.from(modal.children).find((child) => child.classList.contains('staff-editor-body'));
    if (existingBody) {
      existingBody.classList.add('modal-scroll-area');
      modal.classList.add('is-scroll-framed');
      return;
    }

    const header = Array.from(modal.children).find((child) =>
      child.classList.contains('modal-title') || child.classList.contains('results-modal-header')
    );
    const footer = Array.from(modal.children).find((child) => child.classList.contains('modal-actions'));
    const content = Array.from(modal.children).filter((child) => child !== header && child !== footer);

    if (!content.length) return;

    const scrollArea = document.createElement('div');
    scrollArea.className = 'modal-scroll-area';
    modal.insertBefore(scrollArea, footer || null);
    content.forEach((child) => scrollArea.appendChild(child));
    modal.classList.add('is-scroll-framed');
  }

  let openSelect = null;
  let openDate = null;
  let selectUiCounter = 0;
  let dateUiCounter = 0;
  const selectUiSelector = '.modal select, #scheduleTeacherSelect, #scheduleRoomSelect, #bookingStatusFilter, #roleFilter, #statusFilter, #staffRoleFilter, #sFacultyFilter, #gFlow, #gGroup, #evalCourse, #evalSpecialty, #evalGroup, #attCourse, #attSpecialty, #attGroup, .teacher-lesson-list .lesson-para-input, #tab-students #sCourse, #tab-students #sSpecialty, #tab-students #sGroup';
  const dateUiSelector = '.teacher-lesson-list .lesson-date-input';

  function closeSelectUi() {
    if (!openSelect) return;
    openSelect.menu.hidden = true;
    openSelect.button.setAttribute('aria-expanded', 'false');
    openSelect.wrapper.classList.remove('is-open');
    openSelect = null;
  }

  function enhanceSelect(select) {
    if (select.multiple || select.dataset.selectUi === 'ready') return;
    select.dataset.selectUi = 'ready';
    select.classList.add('select-ui-native');

    const wrapper = document.createElement('div');
    wrapper.className = 'select-ui';
    if (select.id) wrapper.classList.add(`select-ui--${select.id}`);
    if (select.classList.contains('lesson-para-input')) wrapper.classList.add('select-ui--lesson-para');
    select.parentNode.insertBefore(wrapper, select);
    wrapper.appendChild(select);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'select-ui-trigger';
    button.setAttribute('aria-haspopup', 'listbox');
    button.setAttribute('aria-expanded', 'false');
    button.innerHTML = '<span></span><i aria-hidden="true"></i>';
    wrapper.appendChild(button);

    const menu = document.createElement('div');
    menu.className = 'select-ui-menu';
    if (select.id) menu.classList.add(`select-ui-menu--${select.id}`);
    if (select.classList.contains('lesson-para-input')) menu.classList.add('select-ui-menu--lesson-para');
    menu.id = `selectUiMenu${selectUiCounter++}`;
    menu.setAttribute('role', 'listbox');
    menu.hidden = true;
    document.body.appendChild(menu);
    button.setAttribute('aria-controls', menu.id);

    function render() {
      const options = Array.from(select.options);
      const selected = options[select.selectedIndex] || options[0];
      button.querySelector('span').textContent = selected?.textContent || 'Выберите значение';
      button.disabled = select.disabled;
      button.classList.toggle('is-placeholder', !selected?.value);
      menu.innerHTML = '';
      options.forEach((option, optionIndex) => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = `select-ui-option${option.selected ? ' is-selected' : ''}`;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', String(option.selected));
        item.disabled = option.disabled;
        item.dataset.index = String(optionIndex);
        item.dataset.value = option.value;
        const label = document.createElement('span');
        label.textContent = option.textContent;
        item.appendChild(label);
        if (option.selected) {
          const check = document.createElement('i');
          check.textContent = '✓';
          check.setAttribute('aria-hidden', 'true');
          item.appendChild(check);
        }
        item.addEventListener('click', () => {
          select.selectedIndex = optionIndex;
          select.dispatchEvent(new Event('input', { bubbles: true }));
          select.dispatchEvent(new Event('change', { bubbles: true }));
          render();
          closeSelectUi();
          button.focus();
        });
        menu.appendChild(item);
      });
    }

    function open() {
      closeSelectUi();
      render();
      menu.hidden = false;
      button.setAttribute('aria-expanded', 'true');
      wrapper.classList.add('is-open');
      const rect = button.getBoundingClientRect();
      menu.style.width = `${Math.max(rect.width, 190)}px`;
      menu.style.maxHeight = `${Math.max(120, Math.min(280, window.innerHeight - 32))}px`;
      const menuHeight = menu.offsetHeight;
      const opensUp = window.innerHeight - rect.bottom < menuHeight + 12 && rect.top > menuHeight;
      menu.classList.toggle('opens-up', opensUp);
      menu.style.left = `${Math.max(12, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 12))}px`;
      menu.style.top = `${opensUp ? rect.top - menuHeight - 7 : rect.bottom + 7}px`;
      openSelect = { select, wrapper, button, menu };
      menu.querySelector('.is-selected:not(:disabled), .select-ui-option:not(:disabled)')?.scrollIntoView({ block: 'nearest' });
    }

    button.addEventListener('click', () => openSelect?.select === select ? closeSelectUi() : open());
    button.addEventListener('keydown', (event) => {
      if (!['ArrowDown', 'ArrowUp', 'Enter', ' ', 'Escape'].includes(event.key)) return;
      if (event.key === 'Escape') { closeSelectUi(); return; }
      event.preventDefault();
      if (openSelect?.select !== select) open();
      const items = Array.from(menu.querySelectorAll('.select-ui-option:not(:disabled)'));
      const current = items.indexOf(document.activeElement);
      if (event.key === 'ArrowUp') items[Math.max(0, current < 0 ? items.length - 1 : current - 1)]?.focus();
      else if (event.key === 'ArrowDown') items[Math.min(items.length - 1, current + 1)]?.focus();
      else menu.querySelector('.is-selected:not(:disabled), .select-ui-option:not(:disabled)')?.focus();
    });
    select.addEventListener('change', render);
    select.addEventListener('focus', () => button.focus());
    new MutationObserver(render).observe(select, { childList: true, subtree: true, characterData: true, attributes: true });
    render();
  }

  function closeDateUi() {
    if (!openDate) return;
    openDate.menu.hidden = true;
    openDate.button.setAttribute('aria-expanded', 'false');
    openDate.wrapper.classList.remove('is-open');
    openDate = null;
  }

  function enhanceDate(input) {
    if (input.dataset.dateUi === 'ready') return;
    input.dataset.dateUi = 'ready';
    input.classList.add('date-ui-native');

    const wrapper = document.createElement('div');
    wrapper.className = 'date-ui';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    const textInput = document.createElement('input');
    textInput.type = 'text';
    textInput.className = 'date-ui-text';
    textInput.placeholder = 'ДД.ММ.ГГГГ';
    textInput.inputMode = 'numeric';
    textInput.setAttribute('aria-label', 'Дата занятия');
    wrapper.appendChild(textInput);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'date-ui-trigger';
    button.setAttribute('aria-haspopup', 'dialog');
    button.setAttribute('aria-expanded', 'false');
    button.title = 'Открыть календарь';
    button.innerHTML = '<i aria-hidden="true"></i>';
    wrapper.appendChild(button);

    const menu = document.createElement('div');
    menu.className = 'date-ui-menu';
    menu.id = `dateUiMenu${dateUiCounter++}`;
    menu.setAttribute('role', 'dialog');
    menu.setAttribute('aria-label', 'Выбор даты');
    menu.hidden = true;
    document.body.appendChild(menu);
    button.setAttribute('aria-controls', menu.id);

    const parseDate = (value) => {
      const parts = String(value || '').split('-').map(Number);
      return parts.length === 3 && parts.every(Number.isFinite) ? new Date(parts[0], parts[1] - 1, parts[2]) : null;
    };
    const parseTypedDate = (value) => {
      const match = String(value || '').trim().match(/^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{4})$/);
      if (!match) return null;
      const date = new Date(Number(match[3]), Number(match[2]) - 1, Number(match[1]));
      return date.getFullYear() === Number(match[3]) && date.getMonth() === Number(match[2]) - 1 && date.getDate() === Number(match[1]) ? date : null;
    };
    const dateValue = (date) => `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
    let viewDate = parseDate(input.value) || new Date();

    function renderButton() {
      const selected = parseDate(input.value);
      textInput.value = selected ? new Intl.DateTimeFormat('ru-RU').format(selected) : '';
      textInput.classList.remove('is-invalid');
    }

    function commitTypedDate() {
      const value = textInput.value.trim();
      if (!value) { selectDate(null, false); return true; }
      const date = parseTypedDate(value);
      if (!date) { textInput.classList.add('is-invalid'); return false; }
      selectDate(date, false);
      return true;
    }

    function selectDate(date, focusField = true) {
      input.value = date ? dateValue(date) : '';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
      renderButton();
      closeDateUi();
      if (focusField) textInput.focus();
    }

    function renderCalendar() {
      const year = viewDate.getFullYear();
      const month = viewDate.getMonth();
      const selectedValue = input.value;
      const todayValue = dateValue(new Date());
      const firstDay = new Date(year, month, 1);
      const startOffset = (firstDay.getDay() + 6) % 7;
      const startDate = new Date(year, month, 1 - startOffset);
      const title = new Intl.DateTimeFormat('ru-RU', { month: 'long', year: 'numeric' }).format(firstDay);

      menu.innerHTML = `<div class="date-ui-header"><button type="button" data-action="prev" aria-label="Предыдущий месяц"><span></span></button><strong>${title}</strong><button type="button" data-action="next" aria-label="Следующий месяц"><span></span></button></div><div class="date-ui-weekdays"><span>Пн</span><span>Вт</span><span>Ср</span><span>Чт</span><span>Пт</span><span>Сб</span><span>Вс</span></div><div class="date-ui-days"></div><div class="date-ui-footer"><button type="button" data-action="clear">Очистить</button><button type="button" data-action="today">Сегодня</button></div>`;
      const days = menu.querySelector('.date-ui-days');
      for (let index = 0; index < 42; index++) {
        const date = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate() + index);
        const value = dateValue(date);
        const day = document.createElement('button');
        day.type = 'button';
        day.textContent = String(date.getDate());
        day.dataset.value = value;
        day.className = 'date-ui-day';
        day.classList.toggle('is-outside', date.getMonth() !== month);
        day.classList.toggle('is-today', value === todayValue);
        day.classList.toggle('is-selected', value === selectedValue);
        day.setAttribute('aria-label', new Intl.DateTimeFormat('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' }).format(date));
        day.addEventListener('click', () => selectDate(date));
        days.appendChild(day);
      }
      menu.querySelector('[data-action="prev"]').addEventListener('click', () => { viewDate = new Date(year, month - 1, 1); renderCalendar(); });
      menu.querySelector('[data-action="next"]').addEventListener('click', () => { viewDate = new Date(year, month + 1, 1); renderCalendar(); });
      menu.querySelector('[data-action="today"]').addEventListener('click', () => selectDate(new Date()));
      menu.querySelector('[data-action="clear"]').addEventListener('click', () => selectDate(null));
    }

    function open() {
      closeSelectUi();
      closeDateUi();
      viewDate = parseDate(input.value) || new Date();
      renderCalendar();
      menu.hidden = false;
      button.setAttribute('aria-expanded', 'true');
      wrapper.classList.add('is-open');
      const rect = button.getBoundingClientRect();
      const menuHeight = menu.offsetHeight;
      const opensUp = window.innerHeight - rect.bottom < menuHeight + 12 && rect.top > menuHeight;
      menu.classList.toggle('opens-up', opensUp);
      menu.style.left = `${Math.max(12, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 12))}px`;
      menu.style.top = `${opensUp ? rect.top - menuHeight - 7 : rect.bottom + 7}px`;
      openDate = { input, wrapper, button, menu };
    }

    button.addEventListener('click', () => openDate?.input === input ? closeDateUi() : open());
    textInput.addEventListener('change', commitTypedDate);
    textInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') { event.preventDefault(); commitTypedDate(); }
      if (event.key === 'ArrowDown') { event.preventDefault(); open(); }
    });
    textInput.addEventListener('input', () => textInput.classList.remove('is-invalid'));
    input.addEventListener('change', renderButton);
    input.addEventListener('focus', () => textInput.focus());
    renderButton();
  }

  document.querySelectorAll('.modal').forEach(frameModal);
  document.querySelectorAll(selectUiSelector).forEach(enhanceSelect);
  document.querySelectorAll(dateUiSelector).forEach(enhanceDate);
  document.addEventListener('click', (event) => {
    if (openSelect && !openSelect.wrapper.contains(event.target) && !openSelect.menu.contains(event.target)) closeSelectUi();
    if (openDate && !openDate.wrapper.contains(event.target) && !openDate.menu.contains(event.target)) closeDateUi();
  });
  document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { closeSelectUi(); closeDateUi(); } });
  window.addEventListener('resize', () => { closeSelectUi(); closeDateUi(); });
  document.addEventListener('scroll', (event) => {
    if (!openSelect?.menu.contains(event.target)) closeSelectUi();
    if (!openDate?.menu.contains(event.target)) closeDateUi();
  }, true);

  new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (!(mutation.target instanceof HTMLElement) || !mutation.target.classList.contains('modal-overlay')) return;
      if (mutation.target.classList.contains('open')) {
        mutation.target.querySelectorAll('select[data-select-ui="ready"]').forEach((select) => select.dispatchEvent(new Event('change')));
      } else {
        closeSelectUi();
      }
    });
  }).observe(document.body, { attributes: true, attributeFilter: ['class'], subtree: true });

  new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.removedNodes.forEach((node) => {
        if (!(node instanceof HTMLElement)) return;
        const triggers = node.matches('.select-ui-trigger') ? [node] : Array.from(node.querySelectorAll('.select-ui-trigger'));
        triggers.forEach((trigger) => document.getElementById(trigger.getAttribute('aria-controls'))?.remove());
      });
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof HTMLElement)) return;
        if (node.matches(selectUiSelector)) enhanceSelect(node);
        node.querySelectorAll(selectUiSelector).forEach(enhanceSelect);
        if (node.matches(dateUiSelector)) enhanceDate(node);
        node.querySelectorAll(dateUiSelector).forEach(enhanceDate);
      });
    });
  }).observe(document.body, { childList: true, subtree: true });
})();
