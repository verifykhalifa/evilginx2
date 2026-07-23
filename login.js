const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  await page.goto('https://accounts.google.com/');
  await page.fill('#identifierId', process.argv[2]);
  await page.keyboard.press('Enter');
  await page.waitForSelector('input[type="password"]', { timeout: 30000 });
  console.log('Password field found!');
  await page.fill('input[type="password"]', process.argv[3]);
  await page.keyboard.press('Enter');
  await page.waitForTimeout(3000);
  const cookies = await page.context().cookies();
  console.log(JSON.stringify(cookies));
  await browser.close();
})();