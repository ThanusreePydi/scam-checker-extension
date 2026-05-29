chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "checkSelectedText",
    title: "Check selected text for scam risk",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "checkSelectedText") {
    chrome.storage.local.set({
      selectedTextToCheck: info.selectionText
    });
  }
});