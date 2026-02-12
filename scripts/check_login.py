#!/usr/bin/env python3
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    page = browser.new_page()

    # Visit the site
    page.goto("http://testhtml5.vulnweb.com/")
    print(f"URL: {page.url}")

    # Print all links
    links = page.query_selector_all("a")
    print("Links:")
    for link in links:
        text = link.text_content().strip()
        href = link.get_attribute("href")
        print(f"{text} -> {href}")

    # Look for login-related forms
    forms = page.query_selector_all("form")
    print(f"\nFound {len(forms)} forms:")
    for i, form in enumerate(forms):
        print(f"Form {i + 1}:")
        print(f"  Action: {form.get_attribute('action')}")
        print(f"  Method: {form.get_attribute('method')}")

        inputs = form.query_selector_all("input")
        print(f"  Inputs ({len(inputs)}):")
        for input_elem in inputs:
            input_type = input_elem.get_attribute("type")
            input_name = input_elem.get_attribute("name")
            print(f"    {input_name} ({input_type})")

        buttons = form.query_selector_all("button")
        print(f"  Buttons ({len(buttons)}):")
        for button in buttons:
            button_type = button.get_attribute("type")
            button_text = button.text_content().strip()
            print(f"    {button_text} ({button_type})")

    # Click the login link to see the modal
    page.click("a[href='#myModal']")
    page.wait_for_selector("form[action='/login']")

    # Now check the login form
    login_form = page.query_selector("form[action='/login']")
    print("\nLogin form details:")
    print(f"  HTML: {login_form.inner_html()}")

    submit_button = login_form.query_selector("button")
    if submit_button:
        print(f"  Submit button: {submit_button.outer_html()}")
    else:
        print("  No button found, checking for input type=submit")
        submit_input = login_form.query_selector("input[type='submit']")
        if submit_input:
            print(f"  Submit input: {submit_input.outer_html()}")
        else:
            print("  No submit element found in form")

    browser.close()
