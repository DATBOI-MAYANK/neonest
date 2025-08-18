"use client";

import React, { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import Input from "../components/ui/Input";
import { BookOpen, ExternalLink, Search, Filter, Clock } from "lucide-react";

const articles = [
  {
    id: 1,
    title: "Introducing Solids: A Step-by-Step Guide",
    description: "Learn when and how to introduce solid foods to your baby, with tips for making the transition smooth",
    url: "https://example.com/introducing-solids",
    author: "Dr. Emily Parker",
    readTime: "8 min read",
    publishDate: "2024-03-15",
    category: "feeding",
    tags: ["weaning", "nutrition", "first foods"],
  },
  {
    id: 2,
    title: "Establishing Healthy Sleep Habits",
    description: "Practical advice for helping your baby develop good sleep patterns from the start",
    url: "https://example.com/sleep-habits",
    author: "Sleep Consultant Team",
    readTime: "10 min read",
    publishDate: "2024-02-28",
    category: "sleep",
    tags: ["sleep training", "routine", "newborn"],
  },
  {
    id: 3,
    title: "Baby-Proofing Your Home: The Complete Checklist",
    description: "Essential safety measures to protect your curious crawler and toddler",
    url: "https://example.com/baby-proofing",
    author: "Safety First Organization",
    readTime: "12 min read",
    publishDate: "2024-01-20",
    category: "health",
    tags: ["safety", "childproofing", "home"],
  },
  {
    id: 4,
    title: "Understanding Developmental Milestones",
    description: "What to expect in your baby's first year of growth and development",
    url: "https://example.com/developmental-milestones",
    author: "Dr. Michael Chen",
    readTime: "15 min read",
    publishDate: "2023-12-10",
    category: "development",
    tags: ["growth", "milestones", "first year"],
  },
  {
    id: 5,
    title: "Breastfeeding Tips for New Mothers",
    description: "Expert advice for overcoming common breastfeeding challenges",
    url: "https://example.com/breastfeeding-tips",
    author: "Lactation Consultant Team",
    readTime: "9 min read",
    publishDate: "2024-03-01",
    category: "feeding",
    tags: ["breastfeeding", "newborn", "latching"],
  },
  {
    id: 6,
    title: "The Importance of Tummy Time",
    description: "How tummy time helps your baby's development and ways to make it enjoyable",
    url: "https://example.com/tummy-time",
    author: "Pediatric Physical Therapists",
    readTime: "7 min read",
    publishDate: "2024-02-15",
    category: "development",
    tags: ["motor skills", "play", "development"],
  },
];

const categories = [
  { id: "all", name: "All Resources" },
  { id: "feeding", name: "Feeding & Nutrition" },
  { id: "sleep", name: "Sleep & Rest" },
  { id: "development", name: "Development" },
  { id: "health", name: "Health & Safety" },
];

export default function Resources() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");

  useEffect(() => {
    document.title = "Resources | NeoNest";
  }, []);

  const filteredArticles = articles.filter((article) => {
    const matchesSearch =
      !searchTerm ||
      article.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      article.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      article.tags.some((tag) => tag.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesCategory = selectedCategory === "all" || article.category === selectedCategory;

    return matchesSearch && matchesCategory;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-12">
      <div className="text-center space-y-2">
        <h2 className="text-4xl font-bold dark:text-gray-100 text-gray-800">Parenting Resources</h2>
        <p className="text-lg text-gray-600 dark:text-gray-300">Curated articles to support your parenting journey</p>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 inset-y-0 flex items-center h-full text-gray-400 w-4" />
        <Input
          placeholder="Search articles..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="pl-10 py-2 rounded-xl border border-gray-200  dark:border-gray-600  dark:bg-gray-700 text-gray-900 dark:text-gray-100 shadow-sm focus:ring-2 focus:ring-pink-500 focus:border-pink-500 w-full"
        />
      </div>

      {/* Category Filter */}
      <div className="flex flex-wrap items-center gap-4 bg-white  dark:bg-gray-700 rounded-xl shadow-sm p-4">
        <div className="flex items-center  gap-2">
          <Filter className="w-4 h-4 text-gray-600  dark:text-gray-300" />
          <span className="text-sm font-medium text-gray-600  dark:text-gray-300">Category:</span>
        </div>
        {categories.map((category) => (
          <Button
            key={category.id}
            variant="outline"
            onClick={() => setSelectedCategory(category.id)}
            size="sm"
            className={`rounded-xl text-sm ${selectedCategory === category.id ? "bg-pink-100 text-pink-700 dark:bg-pink-900/30  font-semibold border-pink-500   " : "text-gray-600 dark:text-gray-300 dark:hover:bg-pink-900/20 border-gray-200 hover:bg-gray-200 "}`}>
            {category.name}
          </Button>
        ))}
      </div>

      {/* Articles Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredArticles.map((article) => (
          <Card
            key={article.id}
            className="bg-white border border-gray-200  dark:bg-gray-900   dark:border-gray-600 rounded-2xl shadow-sm hover:shadow-md transition-shadow duration-300 flex flex-col justify-between">
            <CardHeader className="p-4 pb-2">
              <div className="flex items-center justify-between"></div>
              <CardTitle className="text-lg mt-2 hover:text-pink-600 dark:text-gray-200 transition-colors duration-200">{article.title}</CardTitle>
            </CardHeader>

            <CardContent className="px-4 pb-6 pt-0">
              <p className="text-gray-600 dark:text-gray-300  text-sm mb-4">{article.description}</p>

              <div className="space-y-1 mb-4 text-sm text-gray-500 dark:text-gray-300">
                <div>By {article.author}</div>
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {article.readTime}
                  </div>
                  <div>{new Date(article.publishDate).toLocaleDateString("en-GB")}</div>
                </div>
              </div>

              <div className="flex flex-wrap gap-2 mb-4">
                {article.tags.map((tag, index) => (
                  <Badge key={index} variant="secondary" className="text-xs px-2 py-1 rounded-full bg-pink-100  dark:bg-gray-800 text-pink-600">
                    {tag}
                  </Badge>
                ))}
              </div>

              <Button
                className="w-full bg-pink-50 text-pink-600 hover:bg-pink-600 dark:bg-gray-800 dark:hover:bg-pink-600 hover:text-white font-medium rounded-xl transition-all duration-200"
                variant="ghost"
                onClick={() => window.open(article.url, "_blank")}>
                <ExternalLink className="w-4 h-4 mr-2" />
                Read Article
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {filteredArticles.length === 0 && (
        <div className="text-center py-20 space-y-4">
          <p className="text-gray-500 text-lg">No articles found matching your criteria.</p>
          <Button
            variant="outline"
            onClick={() => {
              setSearchTerm("");
              setSelectedCategory("all");
            }}
            className="rounded-xl">
            Clear Filters
          </Button>
        </div>
      )}
    </div>
  );
}
