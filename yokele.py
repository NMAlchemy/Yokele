import snscrape.modules.twitter as sntwitter
from collections import Counter
import re

# Define lifestyle keywords for analysis
lifestyle_keywords = {
    "location": ["home", "work", "office", "commute", "trip", "vacation", "airport", "city", "neighborhood"],
    "routine": ["morning", "coffee", "gym", "workout", "lunch", "dinner", "bedtime", "weekend", "schedule", "busy", "lazy"],
    "hobbies": ["gaming", "books", "reading", "movie", "hiking", "cooking", "art", "music", "concert", "DIY", "photography"],
    "relationships": ["partner", "spouse", "girlfriend", "boyfriend", "kids", "family", "friends", "date", "wedding", "breakup"],
    "work_finance": ["job", "boss", "meeting", "payday", "raise", "broke", "shopping", "budget", "side hustle", "freelance", "promotion"],
    "tech": ["phone", "laptop", "app", "streaming", "Netflix", "password", "update", "Wi-Fi", "gadget", "tech"],
    "health": ["doctor", "sick", "meds", "therapy", "stress", "diet", "vegan", "sleep", "anxiety", "run", "yoga"],
    "purchases": ["bought", "ordered", "Amazon", "deal", "sale", "new car", "clothes", "sneakers", "subscription", "gear"],
    "social": ["party", "bar", "club", "hangout", "travel", "festival", "birthday", "celebrate", "plans", "cancel"],
    "emotions": ["happy", "sad", "angry", "love", "hate", "rant", "politics", "news", "best", "worst", "obsessed"]
}

# Define conclusion templates for each category
conclusion_templates = {
    "location": "May live or frequently visit areas associated with '{}'.",
    "routine": "Likely has a routine involving '{}'.",
    "hobbies": "Interested in '{}' as a hobby.",
    "relationships": "Possibly has a '{}' or focuses on such relationships.",
    "work_finance": "May be involved in work or financial situations tied to '{}'.",
    "tech": "Uses or is interested in technology related to '{}'.",
    "health": "May prioritize or struggle with health aspects like '{}'.",
    "purchases": "Engages in shopping or owns items related to '{}'.",
    "social": "Likely enjoys social activities like '{}'.",
    "emotions": "Expresses or experiences '{}' frequently."
}

def scrape_tweets(username, max_tweets=100):
    """Scrape tweets from a given Twitter username."""
    tweets = []
    try:
        for i, tweet in enumerate(sntwitter.TwitterSearchScraper(f"from:{username}").get_items()):
            if i >= max_tweets:
                break
            tweets.append({
                "date": tweet.date,
                "content": tweet.rawContent,
                "likes": tweet.likeCount,
                "retweets": tweet.retweetCount,
                "replies": tweet.replyCount
            })
        print(f"Scraped {len(tweets)} tweets from {username}")
        return tweets
    except Exception as e:
        print(f"Error scraping tweets: {e}")
        return []

def analyze_tweets(tweets):
    """Analyze tweets for lifestyle keywords and count occurrences."""
    keyword_counts = {category: Counter() for category in lifestyle_keywords.keys()}
    all_text = " ".join(tweet["content"].lower() for tweet in tweets)
    
    for category, keywords in lifestyle_keywords.items():
        for keyword in keywords:
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', all_text))
            if count > 0:
                keyword_counts[category][keyword] = count
    
    return keyword_counts

def generate_summary(keyword_counts, tweets):
    """Generate a summary and conclusions based on keyword counts."""
    summary = f"Analyzed {len(tweets)} tweets. Key findings:\n"
    conclusions = []
    
    for category in lifestyle_keywords.keys():
        if keyword_counts[category]:
            top_keyword, count = keyword_counts[category].most_common(1)[0]
            summary += f"- {category.capitalize()}: '{top_keyword}' ({count} times)\n"
            template = conclusion_templates.get(category, "Has a lifestyle aspect related to '{}' in the {} category.")
            conclusions.append(template.format(top_keyword))
        else:
            summary += f"- {category.capitalize()}: No keywords found\n"
    
    if not any(keyword_counts.values()):
        conclusions.append("No significant lifestyle insights available from tweets.")
    
    return summary, conclusions

def main():
    """Main function to run the OSINT Twitter analysis."""
    username = input("Enter the Twitter username to analyze (without @): ")
    max_tweets = int(input("Enter the number of tweets to scrape (max 1000): "))
    
    if max_tweets > 1000:
        max_tweets = 1000
        print("Max tweets limited to 1000.")
    
    tweets = scrape_tweets(username, max_tweets)
    if not tweets:
        print("No tweets found or error occurred.")
        return
    
    keyword_counts = analyze_tweets(tweets)
    summary, conclusions = generate_summary(keyword_counts, tweets)
    
    print("\n=== Summary ===")
    print(summary)
    print("=== Objective Conclusions ===")
    for i, conclusion in enumerate(conclusions, 1):
        print(f"{i}. {conclusion}")
    
    with open(f"{username}_analysis.txt", "w", encoding="utf-8") as f:
        f.write("=== Summary ===\n")
        f.write(summary)
        f.write("\n=== Objective Conclusions ===\n")
        for i, conclusion in enumerate(conclusions, 1):
            f.write(f"{i}. {conclusion}\n")
    print(f"\nAnalysis saved to {username}_analysis.txt")

if __name__ == "__main__":
    main()
